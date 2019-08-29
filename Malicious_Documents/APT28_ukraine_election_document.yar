rule possible_APT28_ukraine_election_document {
meta:
	description = "Yara rule for ukraine_election_document"
	author = "Cybaze - Yoroi ZLab"
	last_updated = "2019-04-10"
	tlp = "white"
	category = "informational"
strings:
	$a1 = {F6 EC 18 27 58 C5 1E CB 36 B0 79}
	$a2 = {50 4B 03 04 14 00 06}
	$b = "[Content_Types].xml"

condition:
	all of them
}