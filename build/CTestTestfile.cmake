# CMake generated Testfile for 
# Source directory: /home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser
# Build directory: /home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(device_tests "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build/bin/device_tests")
set_tests_properties(device_tests PROPERTIES  WORKING_DIRECTORY "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build" _BACKTRACE_TRIPLES "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;170;add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;176;erasecure_add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;0;")
add_test(block_erase_tests "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build/bin/block_erase_tests")
set_tests_properties(block_erase_tests PROPERTIES  WORKING_DIRECTORY "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build" _BACKTRACE_TRIPLES "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;170;add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;177;erasecure_add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;0;")
add_test(crypto_erase_tests "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build/bin/crypto_erase_tests")
set_tests_properties(crypto_erase_tests PROPERTIES  WORKING_DIRECTORY "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build" _BACKTRACE_TRIPLES "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;170;add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;178;erasecure_add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;0;")
add_test(file_eraser_tests "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build/bin/file_eraser_tests")
set_tests_properties(file_eraser_tests PROPERTIES  WORKING_DIRECTORY "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build" _BACKTRACE_TRIPLES "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;170;add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;179;erasecure_add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;0;")
add_test(ata_nvme_tests "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build/bin/ata_nvme_tests")
set_tests_properties(ata_nvme_tests PROPERTIES  WORKING_DIRECTORY "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/build" _BACKTRACE_TRIPLES "/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;170;add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;180;erasecure_add_test;/home/kali/Desktop/DataSanitization_SIH26-master/secure_eraser/CMakeLists.txt;0;")
