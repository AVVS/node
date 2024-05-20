#ifndef SRC_NODE_HTTP_COMMON_INL_H_
#define SRC_NODE_HTTP_COMMON_INL_H_

#include <algorithm>
#include "env-inl.h"
#include "node.h"
#include "node_http_common.h"
#include "node_mem-inl.h"
#include "node_errors.h"
#include "v8.h"
#include "nghttp2/nghttp2.h"

namespace node {

template <typename T>
NgHeaders<T>::NgHeaders(Environment* env, v8::Local<v8::Array> headers) {
  v8::Local<v8::Value> header_string =
      headers->Get(env->context(), 0).ToLocalChecked();
  v8::Local<v8::Value> header_count =
      headers->Get(env->context(), 1).ToLocalChecked();
  CHECK(header_count->IsUint32());
  CHECK(header_string->IsString());
  count_ = header_count.As<v8::Uint32>()->Value();
  int header_string_len = header_string.As<v8::String>()->Length();

  if (count_ == 0) {
    CHECK_EQ(header_string_len, 0);
    return;
  }

  buf_.AllocateSufficientStorage((alignof(nv_t) - 1) +
                                 count_ * sizeof(nv_t) +
                                 header_string_len);

  char* start = AlignUp(buf_.out(), alignof(nv_t));
  char* header_contents = start + (count_ * sizeof(nv_t));
  nv_t* const nva = reinterpret_cast<nv_t*>(start);

  CHECK_LE(header_contents + header_string_len, *buf_ + buf_.length());
  CHECK_EQ(header_string.As<v8::String>()->WriteOneByte(
               env->isolate(),
               reinterpret_cast<uint8_t*>(header_contents),
               0,
               header_string_len,
               v8::String::NO_NULL_TERMINATION),
           header_string_len);

  size_t n = 0;
  char* p;
  for (p = header_contents; p < header_contents + header_string_len; n++) {
    if (n >= count_) {
      static uint8_t zero = '\0';
      nva[0].name = nva[0].value = &zero;
      nva[0].namelen = nva[0].valuelen = 1;
      count_ = 1;
      return;
    }

    nva[n].name = reinterpret_cast<uint8_t*>(p);
    nva[n].namelen = strlen(p);
    p += nva[n].namelen + 1;
    nva[n].value = reinterpret_cast<uint8_t*>(p);
    nva[n].valuelen = strlen(p);
    p += nva[n].valuelen + 1;
    nva[n].flags = *p;
    p++;
  }
}

// TODO: bool -> enum {request, response, trailers} for correct asserts
// 1. how to fast-lowercase header names?
// 2. separate memory for ng structures and actual char* so we can directly write to it and not have
// std::string concatenation ? directly create array of ng structures?
// 3. ensure all asserts are done
// 4. better symbol access?
// 5. less verbose object iteration, helpers for value processing? same code is repeated for non-array values
// 6. unordered_set - is this what's used? this is give or take JS copy-paste, so maybe not great in c++ ?
template <typename T>
NgHeaders<T>::NgHeaders(Environment* env, v8::Local<v8::Object> headers, bool response) {
  v8::Local<v8::Array> keys;
  auto isolate = env->isolate();
  auto context = env->context();

  // init varialbe
  count_ = 0;

  if (!headers->GetOwnPropertyNames(context).ToLocal(&keys)) {
    return;
  }

  uint32_t keys_length = keys->Length();
  if (keys_length == 0) {
    return;
  }

  // TODO: use #define / constants ? -- whats the actual convention to do it in c++?
  auto kSensitiveHeaders = v8::Symbol::ForApi(isolate, FIXED_ONE_BYTE_STRING(isolate, "nodejs.http2.sensitiveHeaders"));
  std::unordered_set<std::string> singles{};
  std::unordered_set<std::string> neverIndex{};

  v8::Local<v8::Value> maybeNeverIndex;
  // TODO: something more efficient?
  std::string pseudo_header = "";
  std::string reserved_header = "";

  if (headers->Get(context, kSensitiveHeaders).ToLocal(&maybeNeverIndex) && maybeNeverIndex->IsArray()) {
    auto neverIndexArr = maybeNeverIndex.As<v8::Array>();
    for (uint32_t i = 0; i < neverIndexArr->Length(); i++) {
      v8::Local<v8::Value> val;

      if (!neverIndexArr->Get(context, i).ToLocal(&val) || !val->IsString()) {
        continue;
      }

      if (val.As<v8::String>()->Length() == 0) {
        continue;
      }

      // normalized header name
      std::string header_lower = ToLowerStringView(Utf8Value(isolate, val).ToStringView());
      neverIndex.insert(header_lower);
    }
  }

  for (uint32_t i = 0; i < keys_length; i++) {
    auto key = keys->Get(context, i).ToLocalChecked();
    std::string headerValue;

    // TODO: handle symbols
    if (!key->IsString()) {
      continue;
    }

    Utf8Value headerName(isolate, key);
    if (headerName.length() == 0) {
      continue;
    }

    auto value = headers->Get(context, key).ToLocalChecked();

    // empty
    if (value->IsUndefined()) {
      continue;
    }

    // normalized header name
    std::string header_lower = ToLowerStringView(headerName.ToStringView());

    bool isSingleValueHeader = http2_single_value_headers.contains(header_lower);
    bool valueIsArray = value->IsArray();

    if (valueIsArray) {
      auto arrValue = value.As<v8::Array>();
      auto len = arrValue->Length();
      if (len == 0) {
        continue;
      } else if (len == 1) {
        value = arrValue->Get(context, 0).ToLocalChecked();
        if (value->IsUndefined()) {
          continue;
        }

        v8::Local<v8::String> str;
        if (!value->ToString(context).ToLocal(&str)) {
          continue;
        }

        headerValue = *Utf8Value(isolate, str);
        valueIsArray = false;
      } else if (isSingleValueHeader) {
        THROW_ERR_INVALID_ARG_VALUE(env, "is not a single line header");
      }
    } else {
      v8::Local<v8::String> str;
      if (!value->ToString(context).ToLocal(&str)) {
        continue;
      }

      headerValue = *Utf8Value(isolate, str);
    }

    if (isSingleValueHeader) {
      if (singles.contains(header_lower)) {
        THROW_ERR_INVALID_ARG_VALUE(env, "single value header contains multiple entrie");
      }

      singles.insert(header_lower);
    }

    nghttp2_nv_flag flags = neverIndex.contains(header_lower)
      ? nghttp2_nv_flag::NGHTTP2_NV_FLAG_NO_INDEX
      : nghttp2_nv_flag::NGHTTP2_NV_FLAG_NONE;
    auto flags_char = reinterpret_cast<char const*>(&flags);

    if (header_lower.starts_with(':')) {
      if (response) {
        // TODO: ... header_lower != ':status' THROW_ERR
      } else {
        // validate list of headers ...
      }

      reserved_header += header_lower + '\0' + headerValue + '\0';
      reserved_header.push_back(flags_char[0]);

      count_ += 1;
      continue;
    }

    if (header_lower.find_first_of(' ') != std::string::npos) {
      node::THROW_ERR_INVALID_ARG_VALUE(env, "header must not contain spaces");
    }

    // TODO:
    //     if (isIllegalConnectionSpecificHeader(key, value)) {
    //       throw new ERR_HTTP2_INVALID_CONNECTION_HEADERS(key);
    //     }

    if (valueIsArray) {
      auto arrVal = value.As<v8::Array>();
      for (uint32_t j = 0; j < arrVal->Length(); j++) {
        v8::Local<v8::Value> val;
        if (!arrVal->Get(context, j).ToLocal(&val)) {
          continue;
        }

        v8::Local<v8::String> str;
        if (!val->ToString(context).ToLocal(&str)) {
          continue;
        }

        headerValue = *Utf8Value(isolate, str);
        pseudo_header += header_lower + '\0' + headerValue + '\0';
        pseudo_header.push_back(flags_char[0]);

        count_ += 1;
      }

      continue;
    }

    pseudo_header += header_lower + '\0' + headerValue + '\0';
    pseudo_header.push_back(flags_char[0]);

    count_ += 1;
  }

  // concat special headers & pseudo headers
  pseudo_header = reserved_header + pseudo_header;
  size_t header_string_len = pseudo_header.length();

  Debug(env, DebugCategory::HTTP2STREAM,
        "Headers Prepared: length: %d and headers: %d\n",
        header_string_len, count_);

  buf_.AllocateSufficientStorage((alignof(nv_t) - 1) +
                                 count_ * sizeof(nv_t) +
                                 header_string_len);

  char* start = AlignUp(buf_.out(), alignof(nv_t));
  char* header_contents = start + (count_ * sizeof(nv_t));
  nv_t* const nva = reinterpret_cast<nv_t*>(start);

  CHECK_LE(header_contents + header_string_len, *buf_ + buf_.length());

  // pointer to start of content
  auto pStart = &pseudo_header[0];
  std::memcpy(header_contents, pStart, header_string_len);

  size_t n = 0;
  char* p;
  for (p = header_contents; p < header_contents + header_string_len; n++) {
    if (n >= count_) {
      static uint8_t zero = '\0';
      nva[0].name = nva[0].value = &zero;
      nva[0].namelen = nva[0].valuelen = 1;
      count_ = 1;
      return;
    }

    nva[n].name = reinterpret_cast<uint8_t*>(p);
    nva[n].namelen = strlen(p);
    p += nva[n].namelen + 1;
    nva[n].value = reinterpret_cast<uint8_t*>(p);
    nva[n].valuelen = strlen(p);
    p += nva[n].valuelen + 1;
    nva[n].flags = *p;
    p++;
  }

  Debug(env, DebugCategory::HTTP2STREAM, "headers prepared");
}

size_t GetClientMaxHeaderPairs(size_t max_header_pairs) {
  static constexpr size_t min_header_pairs = 1;
  return std::max(max_header_pairs, min_header_pairs);
}

size_t GetServerMaxHeaderPairs(size_t max_header_pairs) {
  static constexpr size_t min_header_pairs = 4;
  return std::max(max_header_pairs, min_header_pairs);
}

template <typename allocator_t>
std::string NgHeaderBase<allocator_t>::ToString() const {
  std::string ret = name();
  ret += " = ";
  ret += value();
  return ret;
}

template <typename T>
bool NgHeader<T>::IsZeroLength(
    NgHeader<T>::rcbuf_t* name,
    NgHeader<T>::rcbuf_t* value) {
  return IsZeroLength(-1, name, value);
}

template <typename T>
bool NgHeader<T>::IsZeroLength(
    int32_t token,
    NgHeader<T>::rcbuf_t* name,
    NgHeader<T>::rcbuf_t* value) {

  if (NgHeader<T>::rcbufferpointer_t::IsZeroLength(value))
    return true;

  const char* header_name = T::ToHttpHeaderName(token);
  return header_name != nullptr ||
      NgHeader<T>::rcbufferpointer_t::IsZeroLength(name);
}

template <typename T>
NgHeader<T>::NgHeader(
    Environment* env,
    NgHeader<T>::rcbuf_t* name,
    NgHeader<T>::rcbuf_t* value,
    uint8_t flags)
    : NgHeader<T>(env, -1, name, value, flags) {}

template <typename T>
NgHeader<T>::NgHeader(
    Environment* env,
    int32_t token,
    NgHeader<T>::rcbuf_t* name,
    NgHeader<T>::rcbuf_t* value,
    uint8_t flags) : env_(env), token_(token), flags_(flags) {
  if (token == -1) {
    CHECK_NOT_NULL(name);
    name_.reset(name, true);  // Internalizable
  }
  CHECK_NOT_NULL(value);
  name_.reset(name, true);  // Internalizable
  value_.reset(value);
}

template <typename T>
NgHeader<T>::NgHeader(NgHeader<T>&& other) noexcept
    : env_(other.env_),
      name_(std::move(other.name_)),
      value_(std::move(other.value_)),
      token_(other.token_),
      flags_(other.flags_) {
  other.token_ = -1;
  other.flags_ = 0;
  other.env_ = nullptr;
}

template <typename T>
void NgHeader<T>::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("name", name_);
  tracker->TrackField("value", value_);
}

template <typename T>
v8::MaybeLocal<v8::String> NgHeader<T>::GetName(
    NgHeader<T>::allocator_t* allocator) const {

  // Not all instances will support using token id's for header names.
  // HTTP/2 specifically does not support it.
  const char* header_name = T::ToHttpHeaderName(token_);

  // If header_name is not nullptr, then it is a known header with
  // a statically defined name. We can safely internalize it here.
  if (header_name != nullptr) {
    auto& static_str_map = env_->isolate_data()->static_str_map;
    v8::Eternal<v8::String> eternal = static_str_map[header_name];
    if (eternal.IsEmpty()) {
      v8::Local<v8::String> str = OneByteString(env_->isolate(), header_name);
      eternal.Set(env_->isolate(), str);
      return str;
    }
    return eternal.Get(env_->isolate());
  }
  return rcbufferpointer_t::External::New(allocator, name_);
}

template <typename T>
v8::MaybeLocal<v8::String> NgHeader<T>::GetValue(
    NgHeader<T>::allocator_t* allocator) const {
  return rcbufferpointer_t::External::New(allocator, value_);
}

template <typename T>
std::string NgHeader<T>::name() const {
  return name_.str();
}

template <typename T>
std::string NgHeader<T>::value() const {
  return value_.str();
}

template <typename T>
size_t NgHeader<T>::length() const {
  return name_.len() + value_.len();
}

template <typename T>
uint8_t NgHeader<T>::flags() const {
  return flags_;
}

}  // namespace node

#endif  // SRC_NODE_HTTP_COMMON_INL_H_
