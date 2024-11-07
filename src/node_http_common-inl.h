#ifndef SRC_NODE_HTTP_COMMON_INL_H_
#define SRC_NODE_HTTP_COMMON_INL_H_

#include "node_http_common.h"
#include "node.h"
#include "node_mem-inl.h"
#include "env-inl.h"
#include "v8.h"
#include "ada.h"

#include <algorithm>
#include "nbytes.h"
#include <nghttp2/nghttp2.h>
#include <unordered_set>

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

  char* start = nbytes::AlignUp(buf_.out(), alignof(nv_t));
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

static constexpr nghttp2_nv_flag HTTP2_NO_FLAG = static_cast<nghttp2_nv_flag>(NGHTTP2_FLAG_NONE);
static constexpr nghttp2_nv_flag HTTP2_NO_INDEX_FLAG = static_cast<nghttp2_nv_flag>(NGHTTP2_NV_FLAG_NO_INDEX);

template <typename T>
NgHeaders<T>::NgHeaders(const uint8_t* data) {
  // Buffer is formatted in this way:
  // 16 bytes "header"
  // | 4 bytes - header count | 4 bytes - header string length |
  // | 4 bytes - pseudo header count | 4 bytes - number of never index headers |
  // rest is header contents structure in this way:
  // {name}\0{value}\0{value}\0\0
  // char[]\0char[]\0char[0]\0\0
  // each name has at least 1 value, double \0 indicates new name
  // if number of never index headers is > 0
  // then following main headers

  auto base = reinterpret_cast<char*>(const_cast<uint8_t*>(data));
  auto int_view = reinterpret_cast<uint32_t*>(base);

  count_ = int_view[0];
  if (count_ == 0) {
    return;
  }

  auto headers_source = base + 16;
  auto header_string_len = int_view[1];
  auto pseudo_headers_count = int_view[2];
  auto never_index_count = int_view[3];

  buf_.AllocateSufficientStorage((alignof(nv_t) - 1) +
                                 count_ * sizeof(nv_t) +
                                 header_string_len);

  char* p_start = nbytes::AlignUp(buf_.out(), alignof(nv_t));
  char* r_start = p_start + (pseudo_headers_count * sizeof(nv_t));

  // write pseudo headers block to nva_psa
  // write regular to nva_reg
  nv_t* const nva_ps = reinterpret_cast<nv_t*>(p_start);
  nv_t* const nva_reg = reinterpret_cast<nv_t*>(r_start);

  // capture contents of name/value pairs so that we can reuse original preallocated pool
  // memcpy(header_contents, headers_source, header_string_len);

  // pointer to what we are reading from continious memory
  char* p;
  size_t r;
  size_t n;

  // prepare sensitive headers
  std::unordered_set<std::string_view> never_index_set{};
  never_index_set.reserve(never_index_count);
  for (r = 0, n = 0, p = headers_source + header_string_len; r < never_index_count; r += 1) {
    auto len = strlen(p);
    ada::idna::ascii_map(p, len); // lowercase
    never_index_set.insert(std::string_view{p, len}); // insert into lookup index
    p += len + 1; // move pointer to next header name
  }

  for (p = headers_source, r = 0, n = 0; p < headers_source + header_string_len; ) {
    bool is_pseudo = pseudo_headers_count > n && p[0] == ':';

    // this has been verified before
    if (is_pseudo) {
      nva_ps[n].name = reinterpret_cast<uint8_t*>(p);
      nva_ps[n].namelen = strlen(p);
      ada::idna::ascii_map(p, nva_ps[n].namelen); // lowercase in-place as we didn't do it earlier

      // set the flag
      nva_ps[n].flags = never_index_set.contains(std::string_view {p, nva_ps[n].namelen})
        ? HTTP2_NO_INDEX_FLAG
        : HTTP2_NO_FLAG;

      p += nva_ps[n].namelen + 1;

      nva_ps[n].value = reinterpret_cast<uint8_t*>(p);
      nva_ps[n].valuelen = strlen(p);
      p += nva_ps[n].valuelen + 1;


      // go over next 2 \0 because all pseudo headers have only 1 allowed value
      p++;
      n++;
    } else {
      auto current_name = reinterpret_cast<uint8_t*>(p);
      size_t name_len = strlen(p);
      ada::idna::ascii_map(p, name_len); // lowercase in-place as we didn't do it earlier
      p += name_len + 1;

      auto flag = never_index_set.contains(std::string_view {reinterpret_cast<char*>(current_name), name_len})
        ? HTTP2_NO_INDEX_FLAG
        : HTTP2_NO_FLAG;

      while (*p != '\0') {
        nva_reg[r].name = current_name;
        nva_reg[r].namelen = name_len;

        // set flag
        nva_reg[r].flags = flag;

        nva_reg[r].value = reinterpret_cast<uint8_t*>(p);
        nva_reg[r].valuelen = strlen(p);

        // move pointer to next value
        p += nva_reg[r].valuelen + 1;
        r++;
      }

      p++;
    }
  }
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
