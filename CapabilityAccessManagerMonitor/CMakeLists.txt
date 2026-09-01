cmake_minimum_required(VERSION 3.15)
project(CapabilityMonitor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SQLite3 REQUIRED)

set(CAPABILITY_MONITOR_CORE_SOURCES
    snapshot.cpp
    analyzer.cpp
    detection_result.cpp
    detector_pipeline.cpp
    risk_scoring.cpp
    detector.cpp
    baseline.cpp
    alert_manager.cpp
    logger.cpp
    runtime_config.cpp
    utils.cpp
)

add_library(CapabilityMonitorCore STATIC ${CAPABILITY_MONITOR_CORE_SOURCES})
target_include_directories(CapabilityMonitorCore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(CapabilityMonitorCore PUBLIC SQLite::SQLite3)
target_compile_features(CapabilityMonitorCore PUBLIC cxx_std_17)

add_executable(CapabilityAccessManagerMonitor service_main.cpp)
target_link_libraries(CapabilityAccessManagerMonitor PRIVATE CapabilityMonitorCore)
target_compile_features(CapabilityAccessManagerMonitor PRIVATE cxx_std_17)

if(MSVC)
    target_compile_options(CapabilityMonitorCore PRIVATE /W4 /permissive-)
    target_compile_options(CapabilityAccessManagerMonitor PRIVATE /W4 /permissive-)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(CapabilityMonitorTests tests/monitor_tests.cpp)
    target_link_libraries(CapabilityMonitorTests PRIVATE CapabilityMonitorCore)
    target_compile_features(CapabilityMonitorTests PRIVATE cxx_std_17)
    add_test(NAME CapabilityMonitorTests COMMAND CapabilityMonitorTests)
endif()
