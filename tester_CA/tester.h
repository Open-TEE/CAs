#ifndef TESTER_H
#define TESTER_H
#include <string>
#include <vector>
#include "tee_client_api.h"

struct TestData {
   std::string input = "";
   uint32_t input_row = 0;
   uint32_t input_length = 0;
   std::string expected_output = "";
   uint32_t expected_output_row = 0;
   uint32_t expected_output_length = 0;
};
enum CryptoAlgorithm {
   SHA1,
   SHA224
};

class Tester
{
public:
   Tester(){}
   ~Tester(){}
   bool runTests(const std::vector<TestData> &testDataVector, const CryptoAlgorithm algorithmToTest, uint32_t longestInput );
   static std::string hex_to_string(std::string hexString);
   static std::string cstring_to_hexstring(const char *str, uint strLength);
};

#endif // TESTER_H

