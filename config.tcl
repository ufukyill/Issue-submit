# User config
set ::env(DESIGN_NAME) top_level

# Change if needed
set ::env(VERILOG_FILES) [glob $::env(DESIGN_DIR)/src/*.v]

# Fill this
set ::env(CLOCK_PERIOD) "0.2"
set ::env(CLOCK_PORT) "clock_signals"
set ::env(FP_CORE_UTIL) 50

set filename $::env(DESIGN_DIR)/$::env(PDK)_$::env(STD_CELL_LIBRARY)_config.tcl
if { [file exists $filename] == 1} {
	source $filename
}

