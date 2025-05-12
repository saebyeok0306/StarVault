from eudplib import *


def onPluginStart():
    DoActions([  # Basic DatFile Actions
        SetMemory(0x665CD8, Add, -65536),# sprites:Is Visible  index:146    from 1 To 0
        SetMemory(0x66EF90, Add, 57),# images:Iscript ID  index:210    from 193 To 250
        SetMemory(0x66F284, Add, 25),# images:Iscript ID  index:399    from 225 To 250
        SetMemory(0x66F288, Add, 24),# images:Iscript ID  index:400    from 226 To 250
        SetMemory(0x664DF4, Add, -1792),# orders:Animation  index:181    from 7 To 0
    ])

