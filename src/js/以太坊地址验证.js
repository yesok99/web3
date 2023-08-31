
function toChecksumAddress (address) {

	address = address.toLowerCase().replace('0x', '')
	
	var hash = web3.utils.keccak256(address).replace(/^0x/i, "")
	
	var ret = '0x'
	
	for (var i = 0; i < address.length; i++) {
	
		if (parseInt(hash[i], 16) >= 8) 
			{ret += address[i].toUpperCase()} 
		else 
		{ret += address[i]}
		
		}
	return ret
}


l = function(e) {
                e = e.replace(/^0x/i, "");
                for (var t = _(e.toLowerCase()).replace(/^0x/i, ""), r = 0; r < 40; r++)
                    if (parseInt(t[r], 16) > 7 && e[r].toUpperCase() !== e[r] || parseInt(t[r], 16) <= 7 && e[r].toLowerCase() !== e[r])
                        return !1;
                return !0
            }