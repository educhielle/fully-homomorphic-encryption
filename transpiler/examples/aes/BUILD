load("//transpiler:fhe.bzl", "fhe_cc_library")
load("@bazel_skylib//:bzl_library.bzl", "bzl_library")

licenses(["notice"])

cc_library(
    name = "aes",
    srcs = ["aes.cc"],
    hdrs = ["aes.h"],
)

fhe_cc_library(
    name = "aes_tfhe",
    src = "aes.cc",
    hdrs = ["aes.h"],
    num_opt_passes = 2,
)

fhe_cc_library(
    name = "aes_interpreted_tfhe",
    src = "aes.cc",
    hdrs = ["aes.h"],
    num_opt_passes = 2,
    transpiler_type = "interpreted_tfhe",
)

fhe_cc_library(
    name = "aes_bool",
    src = "aes.cc",
    hdrs = ["aes.h"],
    num_opt_passes = 2,
    transpiler_type = "bool",
)

cc_binary(
    name = "aes_tfhe_testbench",
    srcs = ["aes_tfhe_testbench.cc"],
    deps = [
        ":aes_tfhe",
        "//transpiler/data:fhe_data",
        "@com_google_xls//xls/common/logging",
        "@com_google_xls//xls/common/status:status_macros",
        "@tfhe//:libtfhe",
    ],
)

cc_binary(
    name = "aes_interpreted_tfhe_testbench",
    srcs = ["aes_tfhe_testbench.cc"],
    copts = ["-DUSE_INTERPRETED_TFHE"],
    deps = [
        ":aes_interpreted_tfhe",
        "//transpiler/data:fhe_data",
        "@com_google_xls//xls/common/logging",
        "@com_google_xls//xls/common/status:status_macros",
        "@tfhe//:libtfhe",
    ],
)

cc_binary(
    name = "aes_bool_testbench",
    srcs = ["aes_bool_testbench.cc"],
    deps = [
        ":aes_bool",
        "//transpiler/data:boolean_data",
        "@com_google_xls//xls/common/logging",
        "@com_google_xls//xls/common/status:status_macros",
    ],
)

cc_test(
    name = "aes_test",
    srcs = ["aes_test.cc"],
    deps = [
        ":aes",
        "@com_google_googletest//:gtest_main",
        "@com_google_xls//xls/common/status:matchers",
    ],
)
