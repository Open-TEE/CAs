#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include "tester.h"

const std::string CONFIG_SEPARATOR = ":";
const std::string CONFIG_BEFORE_DATA_IDENTIFIER = "before_input";
const std::string CONFIG_BEFORE_ENCRYPTED_DATA_IDENTIFIER = "before_expected_output";

struct TestVectorConfiguration {
    std::string before_input;
    std::string before_expected_output;
    bool input_is_hex = true;
};

/**
 * @brief readTestVectorFile reads the given test vector and parses it based on the configuration.
 * @param filename
 * @param configuration
 * @param longestInput
 * @return
 */
std::vector<TestData> readTestVectorFile( const std::string filename,
                                          TestVectorConfiguration configuration, uint32_t &longestInput ) {
    std::string line;
    std::ifstream readFile(filename.c_str());
    std::vector<TestData> organizedVector;
    TestData testData;
    unsigned int lineNumber = 0;
    if(readFile.is_open()) {
        while ( getline (readFile,line) ) {

            ++lineNumber;
            if(line.empty()) {
                continue;
            }
            if(line.at(line.length()-1) == '\r') {
                line.erase(line.length()-1);
            }

            if(testData.input.empty()) {
                int index = line.find(configuration.before_input);

                if(index != -1) {
                    line = line.substr(index + configuration.before_input.length());
                    if(configuration.input_is_hex) {
                        line = Tester::hex_to_string(line);
                    }
                    testData.input = line;
                    testData.input_row = lineNumber;
                    if(line.length() > longestInput) {
                        longestInput = line.length();
                    }
                }

            } else {
                int index = line.find(configuration.before_expected_output);

                if(index != -1) {
                    testData.expected_output = line.substr(index + configuration.before_expected_output.length());
                    testData.expected_output_row = lineNumber;
                    organizedVector.push_back(testData);
                    testData.input = "";
                }
            }
        }
    } else {
        printf("Couldn't read test vector file. Exiting");
        exit(1);
    }
    return organizedVector;
}

/**
 * @brief getTestVectorStructure loads settings for the test vector from a file
 * @param configurationFile
 * @return TestVectorConfiguration that contains the data needed to parse the test vector and run the test inputs.
 */
TestVectorConfiguration getTestVectorStructure(std::string configurationFile) {
    std::string line;
    std::ifstream readFile(configurationFile.c_str());
    std::string configIdentifier;
    std::string configProperty;
    TestVectorConfiguration testVectorStructure;

    if(readFile.is_open()) {
        while ( getline (readFile,line) ) {
            std::size_t configSeparatorPosition = line.find_first_of(CONFIG_SEPARATOR);
            if(configSeparatorPosition != std::string::npos)
                configIdentifier = line.substr(0, configSeparatorPosition);
            configProperty = line.substr(configSeparatorPosition+1, line.length());

            if(configIdentifier.compare(CONFIG_BEFORE_DATA_IDENTIFIER) == 0) {
                testVectorStructure.before_input = configProperty;
            }
            if(configIdentifier.compare(CONFIG_BEFORE_ENCRYPTED_DATA_IDENTIFIER) == 0) {
                testVectorStructure.before_expected_output = configProperty;
            }
        }
    } else {
        printf("Couldn't read configuration file. Exiting");
        exit(1);
    }

    return testVectorStructure;
}



int main( int argc, char *argv[] )
{
    std::string configurationFile;

    std::string testVectorFile;

    if(argc != 3) {
        return 1;
    }
    configurationFile = argv[1];
    testVectorFile = argv[2];

    TestVectorConfiguration testVectorStructure = getTestVectorStructure(configurationFile);

    uint32_t longestInput = 0;
    std::vector<TestData> testDataVector = readTestVectorFile(testVectorFile, testVectorStructure, longestInput);
    Tester* tester = new Tester();
    bool success = tester->runTests(testDataVector, SHA1, longestInput);
    delete tester;
    if(success)
        return 0;
    return 1;
}


