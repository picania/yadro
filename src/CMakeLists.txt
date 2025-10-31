add_executable(yadro
    yadro.cpp
)

target_link_libraries(yadro PRIVATE
    gtest
)

set_property(TARGET yadro PROPERTY CXX_STANDARD 23)
set_property(TARGET yadro PROPERTY COMPILE_WARNING_AS_ERROR ON)
