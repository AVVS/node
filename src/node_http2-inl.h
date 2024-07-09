#ifndef SRC_NODE_HTTP2_INL_H_
#define SRC_NODE_HTTP2_INL_H_

#include <algorithm>
#include "env-inl.h"
#include "node.h"
#include "node_http2.h"
#include "node_mem-inl.h"
#include "node_errors.h"
#include "v8.h"
#include "nghttp2/nghttp2.h"

namespace node {

using v8::Symbol;
using v8::Local;
using v8::Object;
using v8::Array;
using v8::String;
using v8::Value;
using v8::Context;


namespace http2 {

// Stores javascript string in pre-allocated stack-buffer
// if we run out of storage we'll have to allocate on heap
void Http2JSHeadersImpl::AddHeaderImpl(const std::string_view& name,
                                       const std::string_view& value,
                                       const uint8_t flags) {
  bool is_pseudo = name[0] == ':';

  if (is_pseudo) {
    add_pseudo(name, value, flags);
  } else {
    add_regular(name, value, flags);
  }

  ++count_;
}

// We store pseudo headers in a separate stack buffer
// so that we don't need to sort later on - they will
// be added in the same order we receive them and always be ahead of normal headers
void Http2JSHeadersImpl::add_pseudo(const std::string_view& name,
                                    const std::string_view& value,
                                    const uint8_t flags) {
  size_t cur_length = pseudo_headers_.length();
  size_t name_length = name.length();
  size_t value_length = value.length();
  size_t required_capacity = (name_length + value_length + 1) + cur_length;

  pseudo_headers_.AllocateSufficientStorage(required_capacity);
  if (pseudo_headers_.capacity() < required_capacity) {
    pseudo_headers_.AllocateSufficientStorage(required_capacity * 2);
  }
  pseudo_headers_.SetLength(required_capacity);
  auto headers_ptr_ = pseudo_headers_.out() + cur_length;

  memcpy(headers_ptr_, name.data(), name_length);
  headers_ptr_ += name_length;
  pseudo_nv_pairs_[pseudo_count_ * 2] = name_length;

  memcpy(headers_ptr_, value.data(), value_length);
  headers_ptr_ += value_length;
  pseudo_nv_pairs_[pseudo_count_ * 2 + 1] = value_length;

  // cpy flag value
  headers_ptr_[0] = flags;

  ++pseudo_count_;
}

void Http2JSHeadersImpl::add_regular(const std::string_view& name,
                                     const std::string_view& value,
                                     const uint8_t flags) {
  size_t cur_length = real_headers_.length();
  size_t name_length = name.length();
  size_t value_length = value.length();
  size_t required_capacity = (name_length + value_length + 1) + cur_length;

  if (real_headers_.capacity() < required_capacity) {
    real_headers_.AllocateSufficientStorage(required_capacity * 2);
  }
  real_headers_.SetLength(required_capacity);
  auto headers_ptr_ = real_headers_.out() + cur_length;

  if (regular_nv_pairs_.capacity() < (real_count_ + 1) * 2) {
    regular_nv_pairs_.AllocateSufficientStorage((real_count_ + 1) * 4);
  }
  regular_nv_pairs_.SetLength((real_count_ + 1) * 2);
  auto regular_nv_pairs_ptr_ = regular_nv_pairs_.out() + (real_count_ * 2);

  memcpy(headers_ptr_, name.data(), name_length);
  headers_ptr_ += name_length;
  regular_nv_pairs_ptr_[0] = name_length;

  memcpy(headers_ptr_, value.data(), value_length);
  headers_ptr_ += value_length;
  regular_nv_pairs_ptr_[1] = value_length;

  // cpy flag value
  headers_ptr_[0] = flags;

  ++real_count_;
}

void Http2JSHeadersImpl::Prepare() {
  if (count_ == 0) {
    return;
  }

  buf_.AllocateSufficientStorage((alignof(nv_t) - 1) +
                                 count_ * sizeof(nv_t));

  char* start = AlignUp(buf_.out(), alignof(nv_t));
  nv_t* const nva = reinterpret_cast<nv_t*>(start);

  char* p;
  size_t i = 0;
  size_t n = 0;

  for (p = pseudo_headers_.out(); i < pseudo_count_; ++i) {
    nva[i].name = reinterpret_cast<uint8_t*>(p);
    nva[i].namelen = pseudo_nv_pairs_[i * 2];
    p += nva[i].namelen;
    nva[i].value = reinterpret_cast<uint8_t*>(p);
    nva[i].valuelen = pseudo_nv_pairs_[i * 2 + 1];
    p += nva[i].valuelen;
    nva[i].flags = *p;
    p++;
  }

  for (p = real_headers_.out(); n < real_count_; ++i, ++n) {
    nva[i].name = reinterpret_cast<uint8_t*>(p);
    nva[i].namelen = regular_nv_pairs_[n * 2];
    p += nva[i].namelen;
    nva[i].value = reinterpret_cast<uint8_t*>(p);
    nva[i].valuelen = regular_nv_pairs_[n * 2 + 1];
    p += nva[i].valuelen;
    nva[i].flags = *p;
    p++;
  }
}

} // namespace http2

}  // namespace node

#endif  // SRC_NODE_HTTP2_INL_H_

