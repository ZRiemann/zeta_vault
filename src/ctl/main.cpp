#include "ctl/ctl.h"

#include <iostream>

int main(int argc, char **argv) {
  return z::vault::ctl::run(argc, argv, std::cout, std::cerr);
}
