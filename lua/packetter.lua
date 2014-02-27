-- ============================================================================
--
--                                  Packetter                                  
--
-- ============================================================================
do
	packetter = Proto("Packetter", "Packetter is twitter client on Wireshark.")
	
	packetter.dissector = function(buffer, pinfo, tree)
		local request = buffer(0):string()
		
		-- へへへ…文字列に落とし込めばこっちのもんだぜ…
		local method, user, text = string.match(request, "^(%u*)%s/(.*)%s=>%s(.*)%sHTTP/1%.1%c*$")
		
		
		-- 通常のHTTPだった
		if not (method and user and text) then
			-- 怪しい
			local tcp_dissector = Dissector.get("http")
			tcp_dissector:call(buffer(0):tvb(), pinfo, tree)
			return
		end
		
		
		local method_len = string.len(method)
		local user_len = string.len(user)
		local text_len = string.len(text)
		
		-- Tree!
		local subtree = tree:add("Packetter")
		subtree:add(buffer(0, method_len), "Type:", method)
		subtree:add(buffer(method_len + 2, user_len), "User:", user)
		subtree:add(buffer(method_len + user_len + 6, text_len), "Text:", text)
		
		if method == "POST" then
			subtree:add_expert_info(PI_PROTOCOL, PI_WARN, "Submit from other client")
		end
		
		
		-- Info column
		pinfo.cols.protocol = "Packetter"
		pinfo.cols.info = text
	end
	
	tcp_table = DissectorTable.get("tcp.port")
	for i, port in pairs( { 25252, 80 } ) do
		tcp_table:add(port, packetter)
	end
end
