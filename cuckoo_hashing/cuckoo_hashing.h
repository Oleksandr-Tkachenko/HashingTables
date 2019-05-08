#pragma once

//
// \file cuckoo_hashing.h
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

#include "common/hashing.h"

namespace ENCRYPTO {
class CuckooTable : public HashingTable {
 public:
  CuckooTable() = delete;

  CuckooTable(double epsilon) : CuckooTable(epsilon, 0, 0){};

  CuckooTable(double epsilon, std::size_t seed) : CuckooTable(epsilon, 0, seed){};

  CuckooTable(std::size_t num_of_bins) : CuckooTable(0.0f, num_of_bins, 0){};

  CuckooTable(std::size_t num_of_bins, std::size_t seed) : CuckooTable(0.0f, num_of_bins, seed){};

  ~CuckooTable() final{};

  bool Insert(std::uint64_t element) final {
    this->elements_.push_back(element);
    return true;
  }
  bool Insert(const std::vector<std::uint64_t>& elements) final {
    this->elements_.insert(this->elements_.end(), elements.begin(), elements.end());
    return true;
  };

 private:
  CuckooTable(double epsilon, std::size_t num_of_bins, std::size_t seed) {
    this->seed_ = seed;
    this->generator_.seed(this->seed_);

    this->AllocateLoots();
    this->GenerateLoots();
  };

  std::vector<std::uint64_t> hash_table;

  bool AllocateTable() final {
    if (this->num_bins_ == 0 && this->epsilon_ == 0.0f) {
      throw(std::runtime_error(
          "You must set either number of bins or epsilon in the cuckoo hash table"));
    } else if (this->epsilon_ < 0) {
      throw(std::runtime_error("Epsilon cannot be negative in the cuckoo hash table"));
    }

    if (this->epsilon_ > 0) {
      this->num_bins_ = static_cast<uint64_t>(std::ceil(this->elements_.size() * this->epsilon_));
    }
    assert(this->num_bins_ > 0);
    hash_table.resize(this->num_bins_);
    return true;
  }

  bool MapElementsToTable() final { return true; };
};
}