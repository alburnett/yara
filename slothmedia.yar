import "pe"
import "hash"

rule slothfulmedia
{
meta:
      author = "Adam Burnett, InfoSecEagle"
      date = "03 March 2021"
      description = "Attempts to detects SLOTHFULMEDIA Malware executable"
      reports = "DHS/CISA MAR AR20-275A"
      TLP = "White"
        hash1 = "2aa26ed63702ac7b49b775eb5ea045c52bc375a46e0763ff5c135d64ed77ff58"
        hash2 = "64d78eec46c9ddd4b9a366de62ba0f2813267dc4393bc79e4c9a51a9bb7e6273"
        hash3 = "927d945476191a3523884f4c0784fb71c16b7738bd7f2abd1e3a198af403f0ae"
        hash4 = "320cf030b3d28fcddcf0a3ef541dea15599d516cb6edaad53ec9be6b708d15c2"
/*writen to work in Yara 3.0.9, know to work in Yara 4.0.2 (and assumed other versions as well) */

strings:
    $string1 = { FF 88 0E 4E EB BD 8D 85 } 
    $string2 = { 33 C0 8B 4D F0 64 89 0D } 
    $string3 = "etTickCo" ascii
    $string4 = "t_handle" ascii
    $string5 = "www.sdvro.net"

/*  Strings 1 -> 4 obtained by using AutoYara.jar tool https://github.com/NeuromorphicComputationResearchProgram/AutoYara
    String5 from the unix "strings" command against hash4.
*/
condition:
    uint16(0) == 0x5a4d
        and
            (3 of ($string*))
                or
                  (pe.number_of_sections == 6 and
                    for any i in (0..pe.number_of_sections - 1): (
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[1].raw_data_size) == "d6cd352d657372b25707fed98bc3bd0b"
                        and pe.sections[i].name == "header"
                            and
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[1].raw_data_size) == "c036d2e814490871e54dd84e8117e044"
                        and pe.sections[i].name == ".text"
                            and
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[1].raw_data_size) == "2f2819452977bcfd6dcac4389a2cd193"
                        and pe.sections[i].name == ".rdata"
                            and
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[1].raw_data_size) == "554d0cedd69e96ee00c8324ce4da604c"
                        and pe.sections[i].name == ".rscr"
                            and
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[1].raw_data_size) == "ed7fec6ad28b233df4676dad7f306c3c"
                        and pe.sections[i].name == ".reloc")
                    )
}
