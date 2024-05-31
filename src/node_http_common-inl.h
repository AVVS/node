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

using v8::Symbol;
using v8::Local;
using v8::Object;
using v8::Array;
using v8::String;
using v8::Value;
using v8::Context;

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

template <typename T>
NgHeaders<T>::NgHeaders(const v8::FastOneByteString& headers, const uint32_t count) {
  count_ = count;

  if (count == 0) {
    CHECK_EQ(headers.length, 0);
    return;
  }

  buf_.AllocateSufficientStorage((alignof(nv_t) - 1) +
                                 count * sizeof(nv_t) +
                                 headers.length);

  char* start = AlignUp(buf_.out(), alignof(nv_t));
  char* header_contents = start + (count * sizeof(nv_t));
  nv_t* const nva = reinterpret_cast<nv_t*>(start);

  CHECK_LE(header_contents + headers.length, *buf_ + buf_.length());
  memcpy(header_contents, headers.data, headers.length);

  size_t n = 0;
  char* p;
  for (p = header_contents; p < header_contents + headers.length; n++) {
    nva[n].name = reinterpret_cast<uint8_t*>(p);
    nva[n].namelen = strlen(p); // TODO: precalculate
    p += nva[n].namelen + 1;
    nva[n].value = reinterpret_cast<uint8_t*>(p);
    nva[n].valuelen = strlen(p); // TODO: precalculate
    p += nva[n].valuelen + 1;
    nva[n].flags = *p;
    p++;
  }
}

static const size_t te_hash = std::hash<std::string_view>{}("te");
static const size_t status_hash = std::hash<std::string_view>{}(":status");
static const std::unordered_set<size_t> ng_forbidden_headers{
  std::hash<std::string_view>{}("connection"),
  std::hash<std::string_view>{}("upgrade"),
  std::hash<std::string_view>{}("http2-settings"),
  std::hash<std::string_view>{}("keep-alive"),
  std::hash<std::string_view>{}("proxy-connection"),
  std::hash<std::string_view>{}("transfer-encoding"),
};
static const std::unordered_set<size_t> ng_valid_pseudo_headers{
  std::hash<std::string_view>{}(":status"),
  std::hash<std::string_view>{}(":method"),
  std::hash<std::string_view>{}(":authority"),
  std::hash<std::string_view>{}(":scheme"),
  std::hash<std::string_view>{}(":path"),
  std::hash<std::string_view>{}(":protocol")
};
static const size_t ng_valid_pseudo_headers_size = ng_valid_pseudo_headers.size();

MUST_USE_RESULT inline bool VALIDATE_FOR_ILLEGAL_CONNECTION_SPECIFIC_HEADER(
        v8::Isolate*& isolate,
        const std::string_view header,
        const size_t hash,
        const std::string_view value) noexcept {
  if (UNLIKELY(ng_forbidden_headers.contains(hash) ||
      (hash == te_hash && value != "trailers"))) {
    THROW_ERR_HTTP2_INVALID_CONNECTION_HEADERS(isolate,
        "HTTP/1 Connection specific headers are forbidden: \"%s\"", header);
    return false;
  }

  return true;
}

MUST_USE_RESULT inline bool VALIDATE_PSEUDO_HEADER(v8::Isolate* isolate,
                                                   const size_t hash,
                                                   const std::string_view name,
                                                   const http_headers_type type) noexcept {
  if (type == http2_request && ng_valid_pseudo_headers.contains(hash)) {
    return true;
  }

  if (type == http2_response && hash == status_hash) {
    return true;
  }

  THROW_ERR_HTTP2_INVALID_PSEUDOHEADER(isolate, "\"%s\" is an invalid pseudoheader or is used incorrectly", name);
  return false;
}

// Keeps track of how many values special headers
MUST_USE_RESULT inline bool VALIDATE_SINGLES_HEADER(v8::Isolate* isolate,
                                                    std::unordered_set<size_t>& singles,
                                                    const std::string_view header,
                                                    const size_t header_hash) noexcept {
  if (UNLIKELY(singles.contains(header_hash))) {
    THROW_ERR_HTTP2_HEADER_SINGLE_VALUE(isolate, "Header field \"%s\" must only have a single value", header);
    return false;
  }

  singles.insert(header_hash);
  return true;
}

MUST_USE_RESULT inline bool ToString(const Local<Context> context,
                                     const Local<Value>& in,
                                     Local<String>* out) {
  Local<v8::String> str_;
  if (LIKELY(in->IsString())) {
    str_ = in.As<v8::String>();
  } else if (!in->ToString(context).ToLocal(&str_)) {
    return false;
  }

  // TODO: for headers must be true?
  if (UNLIKELY(!str_->IsOneByte())) {
    return false;
  }

  *out = str_;
  return true;
}

// Retrieves list of sensitive headers and creates unordered set of hashes for
// lookup. When a header is matched a flag must be set, which would deny indexing such a header
MUST_USE_RESULT inline std::unordered_set<size_t> GetSensitiveHeaders(
    v8::Isolate* isolate,
    const Local<Context> context,
    const Local<Object>& headers) noexcept {

  std::unordered_set<size_t> neverIndex{};
  auto kSensitiveHeaders = Symbol::ForApi(isolate,
      FIXED_ONE_BYTE_STRING(isolate, "nodejs.http2.sensitiveHeaders"));

  // construct sensitive headers index
  Local<Value> maybeNeverIndex;

  // Headers object may contain an array of header names that are not meant
  // to be indexed for compression purposes (because they are of sensitive nature).
  // That list of header names is passed on via headers[kSensitiveHeaders] on the
  // javascript side. Here we retrieve that array of header names, normalize header names (lowercase)
  // and populate unordered set with hashes of respective values
  // Utf8Value is not used because it allocated char[1024] by default and it's typically an overkill for
  // a header name
  if (!headers->Get(context, kSensitiveHeaders).ToLocal(&maybeNeverIndex) ||
      !maybeNeverIndex->IsArray()) {
    return neverIndex;
  }

  auto neverIndexArr = maybeNeverIndex.As<Array>();
  Local<Value> val;
  Local<String> header;
  MaybeStackBuffer<char, 64> storage{};
  storage.SetLength(64);
  auto buf = storage.out();

  for (uint32_t i = 0, l = neverIndexArr->Length(); i < l; ++i) {
    // header names must be strings, we avoid malformed header names
    if (!neverIndexArr->Get(context, i).ToLocal(&val) ||
        !val->IsString()) {
      continue;
    }

    // verify string is one-byte and extract to local value
    if (!ToString(context, val, &header)) {
      continue;
    }

    size_t str_len = header->Length();

    // if we exceed 64 bytes then allocation will into heap and that will change
      // pointer
    if (str_len > 64) {
      storage.AllocateSufficientStorage(str_len);
      buf = storage.out();
    }

    // use temporary buffer into which we will write one-byte string
    header->WriteOneByte(isolate,
        reinterpret_cast<uint8_t*>(buf),
        0,
        str_len,
        v8::String::WriteOptions::NO_NULL_TERMINATION);

    // lowercase for normalization
    ada::idna::ascii_map(buf, str_len);

    // add hash to the index
    neverIndex.insert(std::hash<std::string_view>{}(std::string_view(buf, str_len)));
  }

  return neverIndex;
}

static constexpr nghttp2_nv_flag Http2NoIndexNoCopyNameValue = static_cast<nghttp2_nv_flag>(
  NGHTTP2_NV_FLAG_NO_INDEX | NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE);

static constexpr nghttp2_nv_flag Http2NoCopyNameValue = static_cast<nghttp2_nv_flag>(
  NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE);

template <typename T>
inline void NgHeaders<T>::WriteNVBlock(nv_t* nva,
                                       const size_t n,
                                       char* header_ptr,
                                       const size_t header_len,
                                       char* value_ptr,
                                       const size_t value_len,
                                       uint8_t flags) {
  nva[n].name = reinterpret_cast<uint8_t*>(header_ptr);
  nva[n].namelen = header_len;
  nva[n].value = reinterpret_cast<uint8_t*>(value_ptr);
  nva[n].valuelen = value_len;
  nva[n].flags = flags;
}

template <typename T>
NgHeaders<T>::NgHeaders(Environment* env, const Local<Object> headers, const http_headers_type header_type) {
  Local<v8::Array> keys;
  auto isolate = env->isolate();
  auto context = env->context();

  // init variable
  count_ = 0;

  // filter by default is static_cast<v8::PropertyFilter>(ONLY_ENUMERABLE | SKIP_SYMBOLS)
  // Object.keys(), if nothing exists - empty header/value pairs
  if (UNLIKELY(!headers->GetPropertyNames(context,
      v8::KeyCollectionMode::kOwnOnly,
      static_cast<v8::PropertyFilter>(v8::PropertyFilter::ONLY_ENUMERABLE | v8::PropertyFilter::SKIP_SYMBOLS),
      v8::IndexFilter::kSkipIndices,
      v8::KeyConversionMode::kNoNumbers).ToLocal(&keys))) {
    valid_ = true;
    return;
  }

  // if we got an array, but it's empty
  uint32_t keys_length = keys->Length();
  if (keys_length == 0) {
    valid_ = true;
    return;
  }

  // sort keys with : in front
  std::unordered_set<size_t> singles{};
  auto neverIndex = GetSensitiveHeaders(isolate, context, headers);

  Local<Value> key_;
  Local<Value> value_;
  Local<String> header;
  Local<String> value;

  std::vector<std::pair<Local<String>, std::vector<Local<String>>>> tmp_nv{};
  size_t storage_required = 0;
  tmp_nv.reserve(keys_length);

  // walk over v8::Object and extra name/value pairs
  // performs verifications and type casts where required
  // due to allocations being expensive we do not convert v8::Strings
  // and simply calculate required storage at this stage, as well as gather
  // name/value pairs for further processing
  for (uint32_t i = 0; i < keys_length; ++i) {
    // verify that we were able to get the key, and key is a string
    if (UNLIKELY(!keys->Get(context, i).ToLocal(&key_) || !key_->IsString())) {
      continue;
    }

    // verify that value at this key exists and its not null or undefined
    if (UNLIKELY(!headers->Get(context, key_).ToLocal(&value_) ||
         value_->IsNullOrUndefined())) {
      continue;
    }

    // extract v8::String into header ptr
    if (UNLIKELY(!ToString(context, key_, &header))) {
      continue;
    }

    // value may be an array or another type that can be casted into string
    if (!value_->IsArray()) {
      if (UNLIKELY(!ToString(context, value_, &value))) {
        continue;
      }

      storage_required += value->Length();
      tmp_nv.emplace_back(header, std::vector<Local<String>>{value});
      ++count_;
    } else {
      Local<v8::Array> arrValue = value_.As<v8::Array>();
      auto l = arrValue->Length();
      std::vector<Local<String>> val_vec{};
      val_vec.reserve(l);

      for (uint32_t j = 0; j < l; j++) {
        if (UNLIKELY(!arrValue->Get(context, j).ToLocal(&value_) ||
            !ToString(context, value_, &value))) {
          continue;
        }

        storage_required += value->Length();
        val_vec.push_back(value);
        ++count_;
      }

      if (val_vec.size() > 0) {
        tmp_nv.emplace_back(header, val_vec);
      } else {
        continue;
      }
    }

    storage_required += header->Length();
  }

  // pre-allocate storage,
  // we will also allocate extra storage for all possible pseudo headers
  // there is a total of at most extra 6 headers // 240 bytes
  // that way we are able to avoid sorting issues
  size_t nv_storage = (count_ + ng_valid_pseudo_headers_size) * sizeof(nv_t);

  buf_.AllocateSufficientStorage((alignof(nv_t) - 1) +
                                 nv_storage +
                                 storage_required);

  char* nva_start = AlignUp(buf_.out(), alignof(nv_t));
  // start of pseudo headers preallocated zone
  nv_t* const nva_pseudo = reinterpret_cast<nv_t*>(nva_start);
  // start of regular headers preallocated zone
  nv_t* const nva = nva_pseudo + ng_valid_pseudo_headers_size;
  // start of "storage" area for headers & it's value, there is no null termination
  // to save space
  char* header_contents = nva_start + nv_storage;

  size_t n = 0;
  size_t n_ps = 0;

  for (const auto& nv_pair: tmp_nv) {
    // extract header name, normalize it by lowercasing it
    auto header = nv_pair.first;
    size_t header_len = header->Length();
    header->WriteOneByte(isolate,
        reinterpret_cast<uint8_t*>(header_contents),
        0,
        header_len,
        String::WriteOptions::NO_NULL_TERMINATION);
    ada::idna::ascii_map(header_contents, header_len);

    auto header_ptr = header_contents;
    header_contents += header_len;

    // con
    std::string_view header_sv{header_ptr, header_len};
    auto header_sv_hash = std::hash<std::string_view>{}(header_sv);

    // determine if it's a pseudo (starts with `:`) and/or a single value header
    const bool isPseudo = header_sv[0] == ':';
    const bool isSingleValueHeader = isPseudo || http2_single_value_headers.contains(header_sv_hash);

    // determine whether we can index the header or not
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

      std::string_view value_sv{value_ptr, value_len};

      // all ':' are single value headers
      if (isPseudo) {
        if (UNLIKELY(!VALIDATE_PSEUDO_HEADER(isolate, header_sv_hash, header_sv, header_type))) return;
        if (UNLIKELY(!VALIDATE_SINGLES_HEADER(isolate, singles, header_sv, header_sv_hash))) return;

        WriteNVBlock(nva_pseudo, n_ps, header_ptr, header_len, value_ptr, value_len, flags);
        ++n_ps;
        continue;
      }

      if (UNLIKELY(header_sv.find_first_of(' ') != std::string::npos)) {
        THROW_ERR_INVALID_HTTP_TOKEN(isolate, "Header name must be a valid HTTP token [\"%s\"]", header_sv);
        return;
      }

      if (UNLIKELY((isSingleValueHeader &&
            !VALIDATE_SINGLES_HEADER(isolate, singles, header_sv, header_sv_hash)) ||
          !VALIDATE_FOR_ILLEGAL_CONNECTION_SPECIFIC_HEADER(isolate, header_sv, header_sv_hash, value_sv))) {
        return;
      }

      WriteNVBlock(nva, n, header_ptr, header_len, value_ptr, value_len, flags);
      ++n;
    }
  }

  // based on the spec we need to ensure that pseudo headers come first
  // we also need to provide a continious block of memory, which contains all
  // name value pair structs, to achieve that we move pseudo headers
  // up to the start of regular headers block
  if (n_ps > 0 && n_ps < ng_valid_pseudo_headers_size) {
    std::memmove(nva - n_ps, nva_pseudo, n_ps * sizeof(nv_t));
  }

  // indicates where the headers block would start
  offset_ = ng_valid_pseudo_headers_size - n_ps;
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
