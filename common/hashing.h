#pragma once

//
// \file hashing.h
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
// \copyright The MIT License. Copyright 2019
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include <cassert>
#include <iostream>
#include <vector>

#include "util.h"

namespace ENCRYPTO {

constexpr bool USE_LUBY_RACKOFF = true;

class HashingTable {
 public:
  HashingTable(const HashingTable & other_table) {};
  HashingTable(double epsilon) {};
  virtual ~HashingTable() = default;

  virtual bool Insert(std::uint64_t element) = 0;
  virtual bool Insert(const std::vector<std::uint64_t> & elements) = 0;

  bool MapElements(){
    AllocateTable();
    MapElementsToTable();
    return true;
  }

 protected:

  HashingTable() = default;

  std::vector<std::uint64_t> elements_;

  double epsilon_ = 1.2f;
  std::size_t num_bins_ = 0;

  std::size_t elem_byte_length_ = 8;
  std::size_t num_of_hash_functions_ = 2;
  std::size_t address_bit_length_ = 64;
  std::size_t seed_ = 0;
  std::mt19937_64 generator_;

  std::size_t num_of_luts_ = 10;
  std::size_t num_of_tables_in_lut_ = 32;
  std::size_t lut_byte_length_ = 8;
  std::size_t lut_addresses_ = 10;
  std::vector<std::vector<std::vector<std::uint64_t>>> luts_;

  virtual bool AllocateTable() = 0;
  virtual bool MapElementsToTable() = 0;

  bool AllocateLoots(){
    luts_.resize(num_of_hash_functions_);
    for(auto & luts : luts_){
      luts.resize(num_of_luts_);
      for(auto & entry : luts){
        entry.resize(lut_addresses_);
      }
    }
    return true;
  }

  bool GenerateLoots() {
    for (auto i = 0ull; i < num_of_hash_functions_; ++i) {
      for (auto j = 0ull; j < num_of_luts_; ++j) {
        for (auto k = 0ull; k < lut_addresses_; k++) {
          luts_.at(i).at(j).at(k) = generator_();
        }
      }
    }

    return true;
  }

  std::vector<std::size_t> HashToPosition(uint8_t *element) {
    std::vector<std::size_t> addresses(num_of_hash_functions_);
    uint64_t tmp = 0;
    for (auto func_i = 0ull; func_i < num_of_hash_functions_; ++func_i) {
      for (auto lut_i = 0ull; lut_i < num_of_luts_; ++lut_i) {
        uint64_t tmp_lut = 0;
        size_t lut_id = ((tmp >> (lut_i * elem_byte_length_ / num_of_luts_)) & 0x000000FFu) %
                        num_of_tables_in_lut_;
        assert(lut_id < num_of_tables_in_lut_);
        tmp_lut = luts_.at(func_i).at(lut_i).at(lut_id);
        tmp ^= tmp_lut;
      }
      return std::move(addresses);
    }
  }
};

}