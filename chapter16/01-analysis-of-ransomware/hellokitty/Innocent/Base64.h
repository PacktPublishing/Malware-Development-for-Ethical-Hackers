#pragma once

#include <windows.h>
#include <stdio.h>
#include <string>

std::string base64_encode(const UCHAR* bytes_to_encode, size_t in_len);
std::string base64_decode(std::string const& encoded_string);