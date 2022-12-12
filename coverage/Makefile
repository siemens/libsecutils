# libsecutils
#
# Copyright (c) Siemens Mobility GmbH, 2021
# 
# Authors:
#  David von Oheimb <david.von.oheimb@siemens.com>
#
# This work is licensed under the terms of the Apache Software License 2.0.  See
# the COPYING file in the top-level directory.           
#               
# SPDX-License-Identifier: Apache-2.0

# Generates HTML test coverage report from .gcda files. These files are
# generated at exit from the program if you use --coverage comp. and link flag.
# Uses LCOV (package lcov).

OUTPUT_DIR = libsecutils-coverage
INPUT_DIR = ../tmp
IGNORE_PATHS = '/usr/include/*'

find_gcda = find $(INPUT_DIR) -type f -name '*.gcda'

.PHONY: all clean open

all:
	# For some reason, sometimes the .gcda files don't have read permissions.
	chmod +r `$(call find_gcda)`

	# Gather the test coverage data.
	lcov --rc lcov_branch_coverage=1 -t $(OUTPUT_DIR) -o coverage.info -c -b .. \
		-d $(INPUT_DIR)

	# Hide files not written by me from the report.
	for I in $(IGNORE_PATHS) ; do \
		lcov --rc lcov_branch_coverage=1 -r coverage.info "$$I" -o coverage.info ; \
	done

	# Generate HTML report.
	genhtml --rc lcov_branch_coverage=1 -o $(OUTPUT_DIR) coverage.info

	# Remove the tmp file.
	rm -f coverage.info

clean:
	# Delete the test report.
	rm -rf $(OUTPUT_DIR) coverage.info
	# Delete the .gcda coverage data files.
	rm -f `$(call find_gcda)`

open: all
	firefox $(OUTPUT_DIR)/index.html &

