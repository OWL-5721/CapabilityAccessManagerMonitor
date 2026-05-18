cmake_minimum_required(VERSION 3.15)
project(CapabilityMonitor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SQLite3 REQUIRED)

add_executable(CapabilityAccessManagerMonitor
    service_main.cpp
    snapshot.cpp
    analyzer.cpp
    detector.cpp
    baseline.cpp
    alert_manager.cpp
    logger.cpp
    utils.cpp
)

target_compile_features(monitor PRIVATE cxx_std_17)

target_include_directories(monitor PRIVATE ${SQLite3_INCLUDE_DIRS})
target_link_libraries(monitor PRIVATE ${SQLite3_LIBRARIES})