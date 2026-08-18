cmake_minimum_required(VERSION 3.16)

# The ML-KEM component is shared with the protocol firmware rather than copied,
# so both builds measure and use the same pinned mlkem-native revision.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../esp32s3-dut/components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(pqc_bench)
