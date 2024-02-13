// Init cards

#include <MFRC522.h>
#include <MFRC522Extended.h>
#include <deprecated.h>
#include <require_cpp11.h>

#define RST_PIN 31  // Configurable, see typical pin layout above
#define SS_PIN 53   // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN);  // Create MFRC522 instance

MFRC522::MIFARE_Key key;

void Authenticate(void) {
    // Authenticate using key B
    MFRC522::StatusCode status;
    Serial.println(F("Authenticating using key B..."));
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, 7, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
}

void setup() {
    Serial.begin(9600);  // Initialize serial communications with the PC
    SPI.begin();         // Init SPI bus
    mfrc522.PCD_Init();  // Init MFRC522
    delay(4);            // Optional delay. Some board do need more time after init to be ready, see Readme

    // Prepare key - all keys are set to FFFFFFFFFFFFh at chip delivery from the factory.
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }
    Serial.println(F("This code will write a MIFARE Classic 1k card"));
}

void loop() {
    // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
    if (!mfrc522.PICC_IsNewCardPresent()) {
        return;
    }

    // Select one of the cards
    if (!mfrc522.PICC_ReadCardSerial()) {
        return;
    }

    Serial.print(F("Card UID:"));
    for (byte i = 0; i < mfrc522.uid.size; i++) {
        Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
        Serial.print(mfrc522.uid.uidByte[i], HEX);
    }
    Serial.println();

    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    Serial.print(F("PICC type: "));
    Serial.print(mfrc522.PICC_GetTypeName(piccType));
    Serial.print(F(" (SAK "));
    Serial.print(mfrc522.uid.sak);
    Serial.print(")\r\n");
    if (piccType != MFRC522::PICC_TYPE_MIFARE_1K && piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        Serial.println(F("This sample only works with MIFARE Classic cards."));
        return;
    }
    // In this sample we use the second sector,
    // that is: sector #1, covering block #4 up to and including block #7
    byte sector = 1;
    byte nameBlock = 4;
    byte uidBlock = 5;
    byte moneyBlock = 6;
    byte trailerBlock = 7;
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);
    int32_t value;

    Authenticate();
    // Show the whole sector as it currently is
    Serial.println(F("Current data in sector:"));
    mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
    Serial.println();
    byte trailerBuffer[] = {
        255, 255, 255, 255, 255, 255,  // Keep default key A
        0, 0, 0,
        0,
        255, 255, 255, 255, 255, 255};  // Keep default key B
    mfrc522.MIFARE_SetAccessBits(&trailerBuffer[6], 4, 6, 6, 3);

    // Read the sector trailer as it is currently stored on the PICC
    Serial.println(F("Reading sector trailer..."));
    status = mfrc522.MIFARE_Read(trailerBlock, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
    // Check if it matches the desired access pattern already;
    // because if it does, we don't need to write it again...
    if (buffer[6] != trailerBuffer[6] || buffer[7] != trailerBuffer[7] || buffer[8] != trailerBuffer[8]) {
        // They don't match (yet), so write it to the PICC
        Serial.println(F("Writing new sector trailer..."));
        status = mfrc522.MIFARE_Write(trailerBlock, trailerBuffer, 16);
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("MIFARE_Write() failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            return;
        }
    }
    Authenticate();
    //  Write block
    status = mfrc522.MIFARE_SetValue(uidBlock, 0);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Write() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    } else
        Serial.println(F("MIFARE_Write() success: "));

    /*  Serial.println(F("Authenticating again using key B..."));
     status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
     if (status != MFRC522::STATUS_OK) {
         Serial.print(F("PCD_Authenticate() failed: "));
         Serial.println(mfrc522.GetStatusCodeName(status));
         return;
     } */

    char name[16] = "Krystof";

    // Write block
    status = mfrc522.MIFARE_Write(nameBlock, (byte*)name, 16);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Write() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    } else
        Serial.println(F("MIFARE_Write() success: "));
    // Write money
    status = mfrc522.MIFARE_SetValue(moneyBlock, 100);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("mifare_SetValue() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Dump the sector data
    mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
    Serial.println();

    // Halt PICC
    mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();

    delay(2000);
}
