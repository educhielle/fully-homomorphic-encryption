load("//transpiler:fhe.bzl", "fhe_cc_library")
load("@bazel_skylib//:bzl_library.bzl", "bzl_library")

licenses(["notice"])

cc_library(
    name = "aes",
    srcs = ["aes.cc"],
    hdrs = ["aes.h"],
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

cc_test(
    name = "aes_test",
    srcs = ["aes_test.cc"],
    deps = [
        ":aes",
        "@com_google_googletest//:gtest_main",
        "@com_google_xls//xls/common/status:matchers",
    ],
)
