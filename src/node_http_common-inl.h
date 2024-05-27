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

static const size_t te_hash = std::hash<std::string>{}("te");
static const size_t status_hash = std::hash<std::string>{}(":status");
static const std::unordered_set<size_t> ng_forbidden_headers{
  std::hash<std::string>{}("connection"),
  std::hash<std::string>{}("upgrade"),
  std::hash<std::string>{}("http2-settings"),
  std::hash<std::string>{}("keep-alive"),
  std::hash<std::string>{}("proxy-connection"),
  std::hash<std::string>{}("transfer-encoding"),
};
static const std::unordered_set<size_t> ng_valid_pseudo_headers{
  std::hash<std::string>{}(":status"),
  std::hash<std::string>{}(":method"),
  std::hash<std::string>{}(":authority"),
  std::hash<std::string>{}(":scheme"),
  std::hash<std::string>{}(":path"),
  std::hash<std::string>{}(":protocol")
};

MUST_USE_RESULT inline bool VALIDATE_FOR_ILLEGAL_CONNECTION_SPECIFIC_HEADER(
        v8::Isolate*& isolate,
        const std::string_view& header,
        const size_t& hash,
        const std::string_view& value) {

  if (ng_forbidden_headers.contains(hash) ||
      (hash == te_hash && value == "trailers")) {
    THROW_ERR_HTTP2_INVALID_CONNECTION_HEADERS(isolate,
        "HTTP/1 Connection specific headers are forbidden: \"%s\"", header);
    return false;
  }

  return true;
}

MUST_USE_RESULT inline bool VALIDATE_PSEUDO_HEADER(v8::Isolate*& isolate,
                                  const size_t& hash,
                                  const std::string_view& name,
                                  const http_headers_type& type) {
  switch (type) {
    case http2_request:
      if (ng_valid_pseudo_headers.contains(hash)) {
        return true;
      }
      break;
    case http2_response:
      if (hash == status_hash) {
        return true;
      }
      break;
    case http2_trailer: break;
  }

  Debug(Realm::GetCurrent(isolate)->env(), DebugCategory::HTTP2STREAM,
    "invalid pseudo header %s - %d vs %d\n", name, hash, status_hash);
  THROW_ERR_HTTP2_INVALID_PSEUDOHEADER(isolate, "\"%s\" is an invalid pseudoheader or is used incorrectly", name);
  return false;
}

MUST_USE_RESULT inline bool VALIDATE_SINGLES_HEADER(v8::Isolate*& isolate,
                                    std::unordered_set<size_t>& singles,
                                    const bool& isSingleValueHeader,
                                    const std::string_view& header,
                                    const size_t& header_hash) {
  if (!isSingleValueHeader) {
    return true;
  }

  if (singles.contains(header_hash)) {
    THROW_ERR_HTTP2_HEADER_SINGLE_VALUE(isolate, "Header field \"%s\" must only have a single value", header);
    return false;
  }

  singles.insert(header_hash);
  return true;
}

MUST_USE_RESULT inline bool ToString(v8::Isolate*& isolate,
                                     const v8::Local<v8::Context>& context,
                                     const v8::Local<v8::Value>& in,
                                     v8::Local<v8::String>* out) {
  v8::Local<v8::String> str_;
  if (in->IsString()) {
    str_ = in.As<v8::String>();
  } else if (!in->ToString(context).ToLocal(&str_)) {
    return false;
  }

  // TODO: for headers must be true?
  if (!str_->IsOneByte()) {
    return false;
  }

  *out = str_;
  return true;
}

MUST_USE_RESULT inline std::unordered_set<size_t> GetSensitiveHeaders(
    v8::Isolate*& isolate,
    const v8::Local<v8::Context>& context,
    const v8::Local<v8::Object>& headers) {

  std::unordered_set<size_t> neverIndex{};

  // TODO: use #define / constants ? -- whats the actual convention to do it in c++?
  auto kSensitiveHeaders = v8::Symbol::ForApi(isolate,
      FIXED_ONE_BYTE_STRING(isolate, "nodejs.http2.sensitiveHeaders"));

  // construct sensitive headers index
  v8::Local<v8::Value> maybeNeverIndex;
  v8::Local<v8::Value> val;
  v8::Local<v8::String> header;

  if (headers->Get(context, kSensitiveHeaders).ToLocal(&maybeNeverIndex) &&
      maybeNeverIndex->IsArray()) {
    auto neverIndexArr = maybeNeverIndex.As<v8::Array>();
    MaybeStackBuffer<char, 64> storage{};

    for (uint32_t i = 0, l = neverIndexArr->Length(); i < l; ++i) {
      if (!neverIndexArr->Get(context, i).ToLocal(&val) || !val->IsString()) {
        continue;
      }

      if (!ToString(isolate, context, val, &header)) {
        continue;
      }

      size_t str_len = header->Length();
      storage.AllocateSufficientStorage(str_len);
      auto buf = storage.out();
      header->WriteOneByte(isolate,
          reinterpret_cast<uint8_t*>(buf),
          0,
          str_len,
          v8::String::WriteOptions::NO_NULL_TERMINATION);
      ada::idna::ascii_map(buf, str_len);

      neverIndex.insert(std::hash<std::string_view>{}(std::string_view(buf, str_len)));
    }
  }

  return neverIndex;
}

inline void GetFirstChar(
  v8::Isolate*& isolate,
  const v8::Local<v8::String>& str,
  char*& buf) {
  str->WriteOneByte(isolate, reinterpret_cast<uint8_t*>(buf), 0, 1, v8::String::WriteOptions::NO_NULL_TERMINATION);
}

static const nghttp2_nv_flag Http2NoIndexNoCopyNameValue = static_cast<nghttp2_nv_flag>(
  NGHTTP2_NV_FLAG_NO_INDEX | NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE);

static const nghttp2_nv_flag Http2NoCopyNameValue = static_cast<nghttp2_nv_flag>(
  NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE);

// TODO: bool -> enum {request, response, trailers} for correct asserts
// 1. how to fast-lowercase header names?
// 2. separate memory for ng structures and actual char* so we can directly write to it and not have
// std::string concatenation ? directly create array of ng structures?
// 3. ensure all asserts are done
// 4. better symbol access?
// 5. less verbose object iteration, helpers for value processing? same code is repeated for non-array values
// 6. unordered_set - is this what's used? this is give or take JS copy-paste, so maybe not great in c++ ?
template <typename T>
NgHeaders<T>::NgHeaders(Environment*& env, v8::Local<v8::Object> headers, http_headers_type header_type) {
  v8::Local<v8::Array> keys;
  auto isolate = env->isolate();
  auto context = env->context();

  // init variable
  count_ = 0;

  // filter by default is static_cast<v8::PropertyFilter>(ONLY_ENUMERABLE | SKIP_SYMBOLS)
  if (!headers->GetPropertyNames(context,
                                 v8::KeyCollectionMode::kOwnOnly,
                                 static_cast<v8::PropertyFilter>(v8::PropertyFilter::ONLY_ENUMERABLE | v8::PropertyFilter::SKIP_SYMBOLS),
                                 v8::IndexFilter::kSkipIndices,
                                 v8::KeyConversionMode::kNoNumbers).ToLocal(&keys)) {
    valid_ = true;
    return;
  }

  uint32_t keys_length = keys->Length();
  if (keys_length == 0) {
    valid_ = true;
    return;
  }

  valid_ = false;

  // sort keys with : in front
  std::unordered_set<size_t> singles{};
  auto neverIndex = GetSensitiveHeaders(isolate, context, headers);

  v8::Local<v8::Value> key_;
  v8::Local<v8::Value> value_;
  v8::Local<v8::String> header;
  v8::Local<v8::String> value;

  std::vector<std::pair<v8::Local<v8::String>, std::vector<v8::Local<v8::String>>>> tmp_nv{};
  size_t storage_required = 0;
  tmp_nv.reserve(keys_length);

  // contains pseudo_buffer
  std::unique_ptr<char[]> cbuf(new char[1]);
  char* buf = cbuf.get();
  bool is_pseudo;

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

    if (!ToString(isolate, context, key_, &header)) {
      continue;
    }

    if (!value_->IsArray()) {
      if (!ToString(isolate, context, value_, &value)) {
        continue;
      }

      // pseudo headers can't have multiple values, so we only check singular values
      GetFirstChar(isolate, header, buf);
      is_pseudo = buf[0] == ':';

      storage_required += value->Length();
      if (is_pseudo) {
        tmp_nv.emplace(tmp_nv.begin(), header, std::vector<v8::Local<v8::String>>{value});
      } else {
        tmp_nv.emplace_back(header, std::vector<v8::Local<v8::String>>{value});
      }
      ++count_;
    } else {
      v8::Local<v8::Array> arrValue = value_.As<v8::Array>();
      auto l = arrValue->Length();
      bool allocated = false;
      std::vector<v8::Local<v8::String>> val_vec{};
      val_vec.reserve(l);

      for (uint32_t j = 0; j < l; j++) {
        if (!arrValue->Get(context, j).ToLocal(&value_) ||
            !ToString(isolate, context, value_, &value)) {
          continue;
        }

        allocated = true;
        storage_required += value->Length();
        val_vec.push_back(value);
        ++count_;
      }

      if (!allocated) {
        continue;
      }

      tmp_nv.emplace_back(header, val_vec);
    }

    storage_required += header->Length();
  }

  // pre-allocate storage, we may have _more_ storage than required
  buf_.AllocateSufficientStorage((alignof(nv_t) - 1) +
                                 count_ * sizeof(nv_t) +
                                 storage_required);

  char* nva_start = AlignUp(buf_.out(), alignof(nv_t));
  nv_t* const nva = reinterpret_cast<nv_t*>(nva_start);
  char* header_contents = nva_start + (count_ * sizeof(nv_t));

  size_t n = 0;
  for (const auto& nv_pair: tmp_nv) {
    auto header = nv_pair.first;
    size_t header_len = header->Length();
    header->WriteOneByte(isolate,
        reinterpret_cast<uint8_t*>(header_contents),
        0,
        header_len,
        v8::String::WriteOptions::NO_NULL_TERMINATION);
    ada::idna::ascii_map(header_contents, header_len);

    auto header_ptr = header_contents;
    header_contents += header_len;

    auto header_sv = std::string_view(header_ptr, header_len);
    auto header_sv_hash = std::hash<std::string_view>{}(header_sv);
    bool isSingleValueHeader = http2_single_value_headers.contains(header_sv_hash);
    uint8_t flags = neverIndex.contains(header_sv_hash)
      ? Http2NoIndexNoCopyNameValue
      : Http2NoCopyNameValue;

    for (const auto& value: nv_pair.second) {
      size_t value_len = value->Length();
      value->WriteOneByte(isolate,
          reinterpret_cast<uint8_t*>(header_contents),
          0,
          value_len,
          v8::String::WriteOptions::NO_NULL_TERMINATION);

      auto value_ptr = header_contents;
      header_contents += value_len;

      auto value_sv = std::string_view(value_ptr, value_len);

      // all ':' are single value headers
      if (header_sv[0] == ':') {
        if (!VALIDATE_PSEUDO_HEADER(isolate, header_sv_hash, header_sv, header_type)) return;
        if (!VALIDATE_SINGLES_HEADER(isolate, singles, isSingleValueHeader, header_sv, header_sv_hash)) return;
      } else if (header_sv.find_first_of(' ') != std::string::npos) {
        THROW_ERR_INVALID_HTTP_TOKEN(isolate, "Header name must be a valid HTTP token [\"%s\"]", header_sv);
        return;
      } else {
        if (!VALIDATE_SINGLES_HEADER(isolate, singles, isSingleValueHeader, header_sv, header_sv_hash)) return;
        if (!VALIDATE_FOR_ILLEGAL_CONNECTION_SPECIFIC_HEADER(isolate, header_sv, header_sv_hash, value_sv)) return;
      }

      nva[n].name = reinterpret_cast<uint8_t*>(header_ptr);
      nva[n].namelen = header_len;
      nva[n].value = reinterpret_cast<uint8_t*>(value_ptr);
      nva[n].valuelen = value_len;
      nva[n].flags = flags;
      ++n;
    }
  }

  valid_ = true;
  Debug(env, DebugCategory::HTTP2STREAM, "headers prepared\n");
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
