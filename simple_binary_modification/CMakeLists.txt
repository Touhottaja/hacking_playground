# Define the board
set(ENV{BOARD} "nrf52840dk_nrf52840")

# Defube nubunyn CMake version
cmake_minimum_required(VERSION 3.20.0)

# Find Zephyr package
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

# Add sources
target_sources(app PRIVATE src/main.c)

# Define the project
project(hello_world)
