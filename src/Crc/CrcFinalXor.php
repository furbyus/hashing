<?php

namespace Furbyus\Hashing\Crc;

final class CrcFinalXor
{
    const CRC_8 = 0x00; //SMBus, iButton
    const CRC_16_CCITT = 0x0000; //X.25, Bluetooth, PPP
    const CRC_16_IBM = 0x0000; //Redes de almacenamiento
    const CRC_32 = 0xFFFFFFFF; //Ethernet, ZIP, PNG
    const CRC_32C = 0xFFFFFFFF; //iSCSI, redes
    const CRC_32_TS = 0x00000000; //Transport Stream, MP4 Ogg
    const CRC_64_ISO = 0x0000000000000000; //Almacenamiento de alto rendimiento
}