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
#include "ada.h"

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

MUST_USE_RESULT inline bool NormalizeString(std::shared_ptr<Utf8Value>& out) {
  auto len = out->length();
  auto str = **out;
  if (ada::idna::ascii_has_upper_case(str, len)) {
    for (size_t i = 0; i < len; ++i) {
      str[i] = ToLower(str[i]);
    }
  }

  return true;
}

MUST_USE_RESULT inline bool ToString(v8::Isolate* isolate, v8::Local<v8::Context>& context, const v8::Local<v8::Value>& in, std::unique_ptr<Utf8Value>& ptr) {
  v8::Local<v8::String> str_;
  if (in->IsString()) {
    str_ = in.As<v8::String>();
  } else if (!in->ToString(context).ToLocal(&str_)) {
    return false;
  }

  ptr = std::make_unique<Utf8Value>(isolate, str_);
  return true;
}

MUST_USE_RESULT inline bool ToString(v8::Isolate* isolate, v8::Local<v8::Context>& context, const v8::Local<v8::Value>& in, std::shared_ptr<Utf8Value>& ptr) {
  v8::Local<v8::String> str_;
  if (in->IsString()) {
    str_ = in.As<v8::String>();
  } else if (!in->ToString(context).ToLocal(&str_)) {
    return false;
  }

  ptr = std::make_shared<Utf8Value>(isolate, str_);
  return true;
}

// TODO: move strings to prehashed unordered_set, and search for hash
// verifies if header is illegal
inline void VALIDATE_FOR_ILLEGAL_CONNECTION_SPECIFIC_HEADER(v8::Isolate* isolate, const std::string_view& name, const std::string_view& value) {
  if (name == "connection" ||
      name == "upgrade" ||
      name == "http2-settings" ||
      name == "keep-alive" ||
      name == "proxy-connection" ||
      name == "transfer-encoding") {
    THROW_ERR_INVALID_ARG_VALUE(isolate, "invalid connection header %s", name);
  }

  if (name == "te" && value != "trailers") {
    THROW_ERR_INVALID_ARG_VALUE(isolate, "invalid trailer header %s", name);
  }
}

// TODO: move strings to prehashed unordered_set, and search for hash
inline void VALIDATE_PSEUDO_HEADER(v8::Isolate* isolate, const std::string_view& name, const http_headers_type& type) {
  switch (type) {
    case http2_request:
      if (name != ":status" &&
          name != ":method" &&
          name != ":authority" &&
          name != ":scheme" &&
          name != ":path" &&
          name != ":protocol") {
        THROW_ERR_INVALID_ARG_VALUE(isolate, "ERR_HTTP2_INVALID_PSEUDOHEADER");
      }
      break;
    case http2_response:
      if (name != ":status") {
        THROW_ERR_INVALID_ARG_VALUE(isolate, "ERR_HTTP2_INVALID_PSEUDOHEADER");
      }
      break;
    case http2_trailer:
      THROW_ERR_INVALID_ARG_VALUE(isolate, "ERR_HTTP2_INVALID_PSEUDOHEADER");
      break;
  }
}

inline void VALIDATE_SINGLES_HEADER(Environment* env, const bool isSingleValueHeader, std::unordered_set<size_t>& singles, const size_t& header_hash) {
  if (!isSingleValueHeader) {
    return;
  }

  if (singles.contains(header_hash)) {
    THROW_ERR_INVALID_ARG_VALUE(env, "single value header contains multiple entries");
  }

  singles.insert(header_hash);
}

MUST_USE_RESULT inline std::unordered_set<int> GetSensitiveHeaders(v8::Isolate* isolate, const v8::Local<v8::Object>& headers) {
  std::unordered_set<int> neverIndex{};

  // TODO: use #define / constants ? -- whats the actual convention to do it in c++?
  auto kSensitiveHeaders = v8::Symbol::ForApi(isolate,
      FIXED_ONE_BYTE_STRING(isolate, "nodejs.http2.sensitiveHeaders"));
  auto context = isolate->GetCurrentContext();

  // construct sensitive headers index
  v8::Local<v8::Value> maybeNeverIndex;
  std::shared_ptr<Utf8Value> header;
  if (headers->Get(context, kSensitiveHeaders).ToLocal(&maybeNeverIndex) &&
      maybeNeverIndex->IsArray()) {
    auto neverIndexArr = maybeNeverIndex.As<v8::Array>();
    v8::Local<v8::Value> val;
    for (uint32_t i = 0, l = neverIndexArr->Length(); i < l; ++i) {
      if (!neverIndexArr->Get(context, i).ToLocal(&val) || !val->IsString()) {
        continue;
      }

      if (!ToString(isolate, context, val, header) || !NormalizeString(header)) {
        continue;
      }

      neverIndex.insert(std::hash<std::string_view>{}(header->ToStringView()));
    }
  }

  return neverIndex;
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
NgHeaders<T>::NgHeaders(Environment* env, v8::Local<v8::Object> headers, http_headers_type header_type) {
  v8::Local<v8::Array> keys;
  auto isolate = env->isolate();
  auto context = env->context();

  // init variable
  count_ = 0;

  // filter by default is static_cast<v8::PropertyFilter>(ONLY_ENUMERABLE | SKIP_SYMBOLS)
  if (!headers->GetOwnPropertyNames(context).ToLocal(&keys)) {
    return;
  }

  uint32_t keys_length = keys->Length();
  if (keys_length == 0) {
    return;
  }

  // sort keys with : in front
  std::unordered_set<size_t> singles{};
  auto neverIndex = GetSensitiveHeaders(isolate, headers);

  v8::Local<v8::Value> key_;
  v8::Local<v8::Value> value_;
  std::shared_ptr<Utf8Value> header;
  std::unique_ptr<Utf8Value> value;

  // pre-sort headers & results into 2 lists
  // verify basic header information
  for (uint32_t i = 0; i < keys_length; ++i) {
    if (!keys->Get(context, i).ToLocal(&key_) || !key_->IsString()) {
      continue;
    }

    if (!headers->Get(context, key_).ToLocal(&value_) ||
         value_->IsNullOrUndefined()) {
      continue;
    }

    if (!ToString(isolate, context, key_, header) ||
        !NormalizeString(header)) {
      continue;
    }

    auto str_view = header->ToStringView();
    auto str_view_hash = std::hash<std::string_view>{}(str_view);
    bool isSingleValueHeader = http2_single_value_headers.contains(str_view_hash);
    uint8_t flags = neverIndex.contains(str_view_hash)
      ? nghttp2_nv_flag::NGHTTP2_NV_FLAG_NO_INDEX
      : nghttp2_nv_flag::NGHTTP2_NV_FLAG_NONE;

    // all ':' are single value headers
    if (str_view[0] == ':') {
      if (!value_->IsString()) {
        THROW_ERR_INVALID_ARG_VALUE(env, "reserved header must be a string");
      }

      if (!ToString(isolate, context, value_, value)) {
        continue;
      }

      VALIDATE_PSEUDO_HEADER(isolate, str_view, header_type);
      VALIDATE_SINGLES_HEADER(env, isSingleValueHeader, singles, str_view_hash);

      headers_.emplace_front(header, std::move(value), flags);
      value = nullptr;

      ++count_;
      continue;
    }

    // verify lack of spaces
    if (str_view.find_first_of(' ') != std::string::npos) {
      THROW_ERR_INVALID_ARG_VALUE(env, "header must not contain spaces");
    }

    // handle non-array standard headers
    if (!value_->IsArray()) {
      if (!ToString(isolate, context, value_, value)) {
        continue;
      }

      VALIDATE_SINGLES_HEADER(env, isSingleValueHeader, singles, str_view_hash);
      VALIDATE_FOR_ILLEGAL_CONNECTION_SPECIFIC_HEADER(isolate, str_view, value->ToStringView());

      headers_.emplace_back(header, std::move(value), flags);
      value = nullptr;

      ++count_;
      continue;
    }

    v8::Local<v8::Array> arrValue = value_.As<v8::Array>();
    v8::Local<v8::Value> arrMember_;
    for (uint32_t j = 0, l = arrValue->Length(); j < l; j++) {
      if (!arrValue->Get(context, j).ToLocal(&arrMember_)) {
        continue;
      }

      if (!ToString(isolate, context, arrMember_, value)) {
        continue;
      }

      VALIDATE_SINGLES_HEADER(env, isSingleValueHeader, singles, str_view_hash);
      VALIDATE_FOR_ILLEGAL_CONNECTION_SPECIFIC_HEADER(isolate, str_view, value->ToStringView());

      headers_.emplace_back(header, std::move(value), flags);
      value = nullptr;

      ++count_;
    }
  }

  // pre-allocate storage, we may have _more_ storage than required
  buf_.AllocateSufficientStorage((alignof(nv_t) - 1) +
                                 count_ * sizeof(nv_t));

  char* start = AlignUp(buf_.out(), alignof(nv_t));
  nv_t* const nva = reinterpret_cast<nv_t*>(start);

  size_t n = 0;
  for (headers_list::const_iterator iter = headers_.begin(); iter != headers_.end(); ++iter) {
    auto& elem = *iter;
    auto& h = *get<0>(elem);
    auto& v = *get<1>(elem);
    auto& f = get<2>(elem);

    nva[n].name = reinterpret_cast<uint8_t*>(*h);
    nva[n].namelen = h.length();
    nva[n].value = reinterpret_cast<uint8_t*>(*v);
    nva[n].valuelen = v.length();
    nva[n].flags = f;

    ++n;
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
