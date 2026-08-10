cmake_minimum_required(VERSION 3.21)

project(NetPeek VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Network Widgets)

qt_add_executable(NetPeek
    src/main.cpp
    src/MainWindow.cpp
    src/MainWindow.h
    src/network/Ipv4Range.cpp
    src/network/Ipv4Range.h
    src/network/HostDiscovery.cpp
    src/network/HostDiscovery.h
    src/network/NetworkInterfaces.cpp
    src/network/NetworkInterfaces.h
    src/network/NetworkScanner.cpp
    src/network/NetworkScanner.h
    src/ports/LocalPortsProvider.cpp
    src/ports/LocalPortsProvider.h
)

target_link_libraries(NetPeek PRIVATE Qt6::Core Qt6::Network Qt6::Widgets)
target_include_directories(NetPeek PRIVATE src)

if(WIN32)
    target_link_libraries(NetPeek PRIVATE iphlpapi ws2_32)
    target_compile_definitions(NetPeek PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

if(APPLE)
    set_target_properties(NetPeek PROPERTIES MACOSX_BUNDLE TRUE)
endif()

install(TARGETS NetPeek
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)
