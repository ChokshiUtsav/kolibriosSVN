if tup.getconfig("NO_FASM") ~= "" then return end
tup.rule("traceroute.asm", "fasm %f %o " .. tup.getconfig("KPACK_CMD"), "traceroute")
