<?php

namespace Furbyus\Hashing\Crc;

final class CrcRefOut
{
    const CRC_8 = 1; //SMBus, iButton
    const CRC_16_CCITT = 0; //X.25, Bluetooth, PPP
    const CRC_16_IBM = 1; //Redes de almacenamiento
    const CRC_32 = 1; //Ethernet, ZIP, PNG
    const CRC_32C = 1; //iSCSI, redes
    const CRC_32_TS = 1; //Transport Stream, MP4 Ogg
    const CRC_64_ISO = 1; //Almacenamiento de alto rendimiento
}