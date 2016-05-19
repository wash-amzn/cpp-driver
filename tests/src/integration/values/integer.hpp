/*
  Copyright (c) 2014-2016 DataStax

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
#ifndef __TEST_INTEGER_HPP__
#define __TEST_INTEGER_HPP__
#include "value_interface.hpp"
#include "test_utils.hpp"

#include <sstream>

namespace test {
namespace driver {

/**
 * 32-bit integer wrapped value
 */
class Integer : public COMPARABLE_VALUE_INTERFACE_VALUE_ONLY(cass_int32_t, Integer) {
public:
  Integer()
    : integer_(0)
    , is_null_(true) {
    set_integer_string();
  }

  Integer(cass_int32_t integer)
    : integer_(integer)
    , is_null_(false) {
    set_integer_string();
  }

  Integer(const CassValue* value)
    : integer_(0)
    , is_null_(false) {
    initialize(value);
    set_integer_string();
  }

  Integer(const std::string& value)
    : integer_(0)
    , is_null_(false) {
    std::string value_trim = Utils::trim(value);

    // Determine if the value is NULL or valid (default is 0 otherwise)
    if (value_trim.empty() ||
        value_trim.compare("null") == 0) {
      is_null_ = true;
    } else {
    //Convert the value
      std::stringstream valueStream(value_trim);
      if ((valueStream >> integer_).fail()) {
        LOG_ERROR("Invalid Integer " << value_trim << ": Using default "
          << integer_);
      }
    }

    set_integer_string();
  }

  Integer(const CassRow* row, size_t column_index)
    : integer_(0)
    , is_null_(false) {
    initialize(row, column_index);
    set_integer_string();
  }

  const char* c_str() const {
    return integer_string_.c_str();
  }

  std::string cql_type() const {
    return std::string("int");
  }

  std::string cql_value() const {
    return integer_string_;
  }

  /**
   * Comparison operation for driver integers
   *
   * @param rhs Right hand side to compare
   * @return -1 if LHS < RHS, 1 if LHS > RHS, and 0 if equal
   */
  int compare(const cass_int32_t& rhs) const {
    if (integer_ < rhs) return -1;
    if (integer_ > rhs) return 1;

    return 0;
  }

  /**
   * Comparison operation for driver integers
   *
   * @param rhs Right hand side to compare
   * @return -1 if LHS < RHS, 1 if LHS > RHS, and 0 if equal
   */
  int compare(const Integer& rhs) const {
    if (is_null_ && rhs.is_null_) return 0;
    return compare(rhs.integer_);
  }

  void statement_bind(Statement statement, size_t index) {
    if (is_null_) {
      ASSERT_EQ(CASS_OK, cass_statement_bind_null(statement.get(), index));
    } else {
      ASSERT_EQ(CASS_OK, cass_statement_bind_int32(statement.get(), index, integer_));
    }
  }

  bool is_null() const {
    return is_null_;
  }

  std::string str() const {
    return integer_string_;
  }

  cass_int32_t value() const {
    return integer_;
  }

  CassValueType value_type() const {
    return CASS_VALUE_TYPE_INT;
  }

protected:
  /**
   * Native driver value
   */
  cass_int32_t integer_;
  /**
   * Native driver value as string
   */
  std::string integer_string_;
  /**
   * Flag to determine if value is NULL
   */
  bool is_null_;

  void initialize(const CassValue* value) {
    // Ensure the value types
    ASSERT_TRUE(value != NULL) << "Invalid CassValue: Value should not be null";
    CassValueType value_type = cass_value_type(value);
    ASSERT_EQ(CASS_VALUE_TYPE_INT, value_type)
      << "Invalid Value Type: Value is not a integer [" << value_type << "]";
    const CassDataType* data_type = cass_value_data_type(value);
    value_type = cass_data_type_type(data_type);
    ASSERT_EQ(CASS_VALUE_TYPE_INT, value_type)
      << "Invalid Data Type: Value->DataType is not a integer";

    // Get the 32-bit integer
    if (cass_value_is_null(value)) {
      is_null_ = true;
    } else {
      ASSERT_EQ(CASS_OK, cass_value_get_int32(value, &integer_))
        << "Unable to Get 32-bit Integer: Invalid error code returned";
      is_null_ = false;
    }
  }

  void initialize(const CassRow* row, size_t column_index) {
    ASSERT_TRUE(row != NULL) << "Invalid Row: Row should not be null";
    initialize(cass_row_get_column(row, column_index));
  }

  /**
   * Set the string value of the integer
   */
  void set_integer_string() {
    if (is_null_) {
      integer_string_ = "null";
    } else {
      std::stringstream integer_string;
      integer_string << integer_;
      integer_string_ = integer_string.str();
    }
  }
};

/**
 * 64-bit integer wrapped value (e.g. bigint)
 */
class BigInteger : public COMPARABLE_VALUE_INTERFACE_VALUE_ONLY(cass_int64_t, BigInteger) {
public:
  BigInteger()
    : integer_(0)
    , is_null_(true) {
    set_integer_string();
  }

  BigInteger(cass_int64_t integer)
    : integer_(integer)
    , is_null_(false) {
    set_integer_string();
  }

  BigInteger(const CassValue* value)
    : integer_(0)
    , is_null_(false) {
    initialize(value);
    set_integer_string();
  }

  BigInteger(const std::string& value)
    : integer_(0)
    , is_null_(false) {
    std::string value_trim = Utils::trim(value);

    // Determine if the value is NULL or valid (default is 0 otherwise)
    if (value_trim.empty() ||
        value_trim.compare("null") == 0) {
      is_null_ = true;
    } else {
      //Convert the value
      std::stringstream valueStream(value_trim);
      if ((valueStream >> integer_).fail()) {
        LOG_ERROR("Invalid Big Integer " << value_trim << ": Using default "
          << integer_);
      }
    }

    set_integer_string();
  }

  BigInteger(const CassRow* row, size_t column_index)
    : integer_(0)
    , is_null_(false) {
    initialize(row, column_index);
    set_integer_string();
  }

  const char* c_str() const {
    return integer_string_.c_str();
  }

  std::string cql_type() const {
    return std::string("bigint");
  }

  std::string cql_value() const {
    return integer_string_;
  }

  /**
   * Comparison operation for driver integers
   *
   * @param rhs Right hand side to compare
   * @return -1 if LHS < RHS, 1 if LHS > RHS, and 0 if equal
   */
  int compare(const cass_int64_t& rhs) const {
    if (integer_ < rhs) return -1;
    if (integer_ > rhs) return 1;

    return 0;
  }

  /**
   * Comparison operation for driver integers
   *
   * @param rhs Right hand side to compare
   * @return -1 if LHS < RHS, 1 if LHS > RHS, and 0 if equal
   */
  int compare(const BigInteger& rhs) const {
    if (is_null_ && rhs.is_null_) return 0;
    return compare(rhs.integer_);
  }

  void statement_bind(Statement statement, size_t index) {
    if (is_null_) {
      ASSERT_EQ(CASS_OK, cass_statement_bind_null(statement.get(), index));
    } else {
      ASSERT_EQ(CASS_OK, cass_statement_bind_int64(statement.get(), index, integer_));
    }
  }

  bool is_null() const {
    return is_null_;
  }

  std::string str() const {
    return integer_string_;
  }

  cass_int64_t value() const {
    return integer_;
  }

  CassValueType value_type() const {
    return CASS_VALUE_TYPE_BIGINT;
  }

protected:
  /**
   * Native driver value
   */
  cass_int64_t integer_;
  /**
   * Native driver value as string
   */
  std::string integer_string_;
  /**
   * Flag to determine if value is NULL
   */
  bool is_null_;

  void initialize(const CassValue* value) {
    // Ensure the value types
    ASSERT_TRUE(value != NULL) << "Invalid CassValue: Value should not be null";
    CassValueType value_type = cass_value_type(value);
    ASSERT_EQ(CASS_VALUE_TYPE_BIGINT, value_type)
      << "Invalid Value Type: Value is not a big integer [" << value_type << "]";
    const CassDataType* data_type = cass_value_data_type(value);
    value_type = cass_data_type_type(data_type);
    ASSERT_EQ(CASS_VALUE_TYPE_BIGINT, value_type)
      << "Invalid Data Type: Value->DataType is not a big integer";

    // Get the 64-bit integer
    if (cass_value_is_null(value)) {
      is_null_ = true;
    } else {
      ASSERT_EQ(CASS_OK, cass_value_get_int64(value, &integer_))
        << "Unable to Get 64-bit Integer: Invalid error code returned";
      is_null_ = false;
    }
  }

  void initialize(const CassRow* row, size_t column_index) {
    ASSERT_TRUE(row != NULL) << "Invalid Row: Row should not be null";
    initialize(cass_row_get_column(row, column_index));
  }

  /**
   * Set the string value of the integer
   */
  void set_integer_string() {
    if (is_null_) {
      integer_string_ = "null";
    } else {
      std::stringstream integer_string;
      integer_string << integer_;
      integer_string_ = integer_string.str();
    }
  }
};

} // namespace driver
} // namespace test

#endif // __TEST_INTEGER_HPP__
