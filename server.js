const express = require("express");
const multer = require("multer");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const QRCode = require("qrcode");
const bip39 = require("bip39");
const fs = require("fs");
const path = require("path");

const app = express();
const upload = multer({ dest: "uploads/" });

app.use(bodyParser.json());
app.use(express.static("public"));

// 日本語ワードリストの設定
bip39.setDefaultWordlist("japanese");

// 暗号化エンドポイント
app.post("/encrypt", upload.single("file"), async (req, res) => {
  try {
    const { ivValue } = req.body;
    const ivInt = parseInt(ivValue, 10);

    if (isNaN(ivInt) || ivInt < 0 || ivInt > 255) {
      return res.status(400).send("IV value must be an integer between 0 and 255.");
    }
    const iv = Buffer.alloc(16, ivInt);

    const filePath = req.file.path;
    const fileData = fs.readFileSync(filePath);

    const key = crypto.randomBytes(32);
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encrypted = cipher.update(fileData);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const base64Output = encrypted.toString("base64");
    const base64FilePath = `public/${req.file.filename}.txt`;
    fs.writeFileSync(base64FilePath, base64Output);

    const seedPhrase = bip39.entropyToMnemonic(key.toString("hex"));
    const qrCodePath = `public/${req.file.filename}-qrcode.png`;
    await QRCode.toFile(qrCodePath, seedPhrase);

    fs.unlinkSync(filePath);

    res.json({
      seedPhrase,
      qrCodeUrl: `/${path.basename(qrCodePath)}`,
      downloadUrl: `/${path.basename(base64FilePath)}`,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error occurred during encryption.");
  }
});

// 復号化エンドポイント
app.post("/decrypt", upload.single("file"), (req, res) => {
  try {
    const { ivValue, seedPhrase } = req.body;

    const ivInt = parseInt(ivValue, 10);
    if (isNaN(ivInt) || ivInt < 0 || ivInt > 255) {
      return res.status(400).send("IV value must be an integer between 0 and 255.");
    }
    const iv = Buffer.alloc(16, ivInt);

    if (!bip39.validateMnemonic(seedPhrase)) {
      return res.status(400).send("Invalid seed phrase.");
    }

    const key = Buffer.from(bip39.mnemonicToEntropy(seedPhrase), "hex");
    const base64FilePath = req.file.path;
    const base64Data = fs.readFileSync(base64FilePath, "utf8");
    const encryptedData = Buffer.from(base64Data, "base64");

    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    const decryptedFilePath = `public/${req.file.filename}-decrypted`;
    fs.writeFileSync(decryptedFilePath, decrypted);

    fs.unlinkSync(base64FilePath);

    res.json({
      downloadUrl: `/${path.basename(decryptedFilePath)}`,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error occurred during decryption.");
  }
});

app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});

