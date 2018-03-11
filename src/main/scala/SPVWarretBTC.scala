import java.io._
import java.{lang, util}
import java.net.Socket
import java.security._
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.{ArrayList, Arrays, Collections}

import org.bouncycastle.util.io.pem.PemWriter

import scala.collection.JavaConversions._
import java.security.spec.ECGenParameterSpec
import java.security.Security
import java.security.interfaces.ECPublicKey
import javax.xml.bind.DatatypeConverter

import scala.util.control.Breaks
import javax.xml.bind.DatatypeConverter
import java.security.spec.ECPublicKeySpec

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECCurve
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.spec.InvalidKeySpecException
import java.io.PrintWriter
import java.io.StringWriter

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger

import org.bouncycastle.crypto.digests.RIPEMD160Digest
import org.bouncycastle.util.encoders.Hex

import scala.io.Source

import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.SignatureException

import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.io.PrintWriter
import java.io.StringWriter
import java.security.Security

class MessageHeader(
                     var magic: Int = 0,
                     var commandName: Array[Byte] = new Array[Byte](12),
                     var payloadSize: Int = 0,
                     var checksum: Array[Byte] = new Array[Byte](4)
                   )

class NetAddr(
               var services: Long = 0,
               var ip: Array[Byte] = new Array[Byte](16),
               var port: Short = 0
             )

class Version(
               var version: Int = 0,
               var services: Long = 0,
               var timestamp: Long = 0,
               var addrRecv: NetAddr = null,
               var addrFrom: NetAddr = null,
               var nonce: Long = 0,
               var userAgent: Array[Char] = null,
               var startHeight: Int = 0,
               var relay: Boolean = false,
               var bytes: Int = 86
             )

class Verack(var commandName: String = "verack")

class OutPoint(
                var hash: Array[Byte] = new Array[Byte](32),
                var index: Int = 0
              )

class TxIn(
            var previousOutput: OutPoint = null,
            var signatureScript: Array[Byte] = null,
            var sequence: Int = 0
          )

class Tx(
          var version: Int = 0,
          var txIn: Array[TxIn] = null,
          var txOut: Array[TxOut] = null,
          var locktime: Int = 0,
          var commandName: String = "tx"
        )

class TxOut(
             var value: Long = 0,
             var pkScript: ByteBuffer = null
           )

class Inv(
           var varlist: Array[Byte] = null,
           var inventory: Array[Inventory] = null
         )

class Inventory(
                 var invType: Int = 0,
                 var hash: Array[Byte] = new Array[Byte](32)
               )

class GetData(
               var varlist: Array[Byte] = null,
               var inventory: Array[Inventory] = null,
               var commandName: String = "getdata"
             )


class MessageHandler(dummy: String = "dummy") {
  val client: Socket = null
  //new Socket("testnet-seed.bitcoin.jonasschnelli.ch", 18333)
  val din: DataInputStream = null
  //new DataInputStream(client.getInputStream())
  var dout: DataOutputStream = null
  //new DataOutputStream(client.getOutputStream())
  val ALPHABET: Array[Char] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray()
  val ENCODED_ZERO = ALPHABET(0)
  var INDEXES: Array[Int] = new Array[Int](128)
  val RANDOM_NUMBER_ALGORITHM = "SHA1PRNG"
  val RANDOM_NUMBER_ALGORITHM_PROVIDER = "SUN"
  val PRIVATE_PATH = "./privateWIF.key"
  val PUBLIC_PATH = "./publicBTCAddress.key"
  var PRIVATE_KEY_WIF: String = null
  var PUBLIC_BTC_ADDRESS: String = null

  val OP_DUP = 0x76.asInstanceOf[Byte]
  val OP_EQUAL = 0x87.asInstanceOf[Byte]
  val OP_EQUALVERIFY = 0x88.asInstanceOf[Byte]
  val OP_HASH160 = 0xA9.asInstanceOf[Byte]
  val OP_CHECKSIG = 0xAC.asInstanceOf[Byte]

  val INV_ERROR = 0
  val INV_MSG_TX = 1
  val INV_MSG_BLOCK = 2
  val INV_MSG_FILTERED_BLOCK = 3
  val INV_MSG_CMPCT_BLOCK = 4

  def this() {
    this("dummy")
    Arrays.fill(INDEXES, -1)
    for (i <- 0 until ALPHABET.length) {
      INDEXES(ALPHABET(i)) = i
    }
  }

  def op_pushdata(obj: Array[Byte]): Array[Byte] = {
    // オペコードが不明なので書き込まない
//    var len = byteToLittleNosin(obj.length.asInstanceOf[Byte])
//    var ret = new Array[Byte](obj.length+1)
//
//    ret(0) = len
//    System.arraycopy(obj, 0, ret, 1, obj.length)
//    return ret
    return obj
  }

  def storedKeyCheck() = {
    // ファイルがあれば読み込み、保存されてなければ新たに生成して保存
    if (checkFile(PRIVATE_PATH)) {
      PRIVATE_KEY_WIF = readFromFile(PRIVATE_PATH)
      PUBLIC_BTC_ADDRESS = readFromFile(PUBLIC_PATH)
      println("keys stored:")
    } else {
      var pairs: ArrayList[Array[Byte]] = getKeyPairBytes()
      PRIVATE_KEY_WIF = encodeWIF(pairs.get(0))
      PUBLIC_BTC_ADDRESS = encodeBTCAddress((pairs.get(1)))
      saveTofFile(PRIVATE_PATH, PRIVATE_KEY_WIF)
      saveTofFile(PUBLIC_PATH, PUBLIC_BTC_ADDRESS)
      println("keys generated:")
    }
    println("private:" + PRIVATE_KEY_WIF)
    println("public:" + PUBLIC_BTC_ADDRESS)
  }

  def readFromFile(path: String): String = {
    var source = Source.fromFile(path)
    val lines = source.getLines
    return lines.next()
  }

  def checkFile(filePath: String): Boolean = {
    val file = new File(filePath)
    if (file.exists()) {
      return true
    } else {
      return false
    }
  }

  def saveTofFile(path: String, str: String) = {
    val file = new PrintWriter(path)
    file.write(str)
    file.close()
  }

  def generatePrivateKey(): Array[Byte] = {
    var secureRandom: SecureRandom = null
    try
      secureRandom = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM, RANDOM_NUMBER_ALGORITHM_PROVIDER)
    catch {
      case e: Exception =>
        val errors = new StringWriter()
        e.printStackTrace(new PrintWriter(errors))
        secureRandom = new SecureRandom()
    }
    var privateKeyCheck = BigInteger.ZERO
    // Bit of magic, move this maybe. This is the max key range.
    val maxKey = new BigInteger("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16)
    // Generate the key, skipping as many as desired.
    val privateKeyAttempt = new Array[Byte](32)
    secureRandom.nextBytes(privateKeyAttempt)
    privateKeyCheck = new BigInteger(1, privateKeyAttempt)
    while ((privateKeyCheck.compareTo(BigInteger.ZERO) == 0) || (privateKeyCheck.compareTo(maxKey) == 1)) {
      secureRandom.nextBytes(privateKeyAttempt)
      privateKeyCheck = new BigInteger(1, privateKeyAttempt)
    }
    privateKeyAttempt
  }

  def generatePublicKey(privateKey: Array[Byte]): Array[Byte] = try {
    val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val pointQ = spec.getG.multiply(new BigInteger(1, privateKey))
    pointQ.getEncoded(false)
  } catch {
    case e: Exception =>
      val errors = new StringWriter
      e.printStackTrace(new PrintWriter(errors))
      new Array[Byte](0)
  }


  def sha256(payload: Array[Byte]): Array[Byte] = {
    val md = MessageDigest.getInstance("SHA-256")
    md.update(payload)
    md.digest()
  }

  def hash256(payload: Array[Byte]): Array[Byte] = {
    sha256(sha256(payload))
  }

  def decodeWIF(str: String): Array[Byte] = {
    var decoded: Array[Byte] = decodeBase58(str)
    return Arrays.copyOfRange(decoded, 1, decoded.length - 4)
  }

  def decodeAddress(str: String): Array[Byte] = {
    return decodeWIF(str)
  }

  def encodeBTCAddress(pubArr: Array[Byte]): String = {
    //    var prefix: Array[Byte] = Array(0x04)
    //    var pub_with_prefix: Array[Byte] = new Array[Byte](pubArr.length + 1)
    //    System.arraycopy(prefix, 0, pub_with_prefix, 0, 1)
    //    System.arraycopy(pubArr, 0, pub_with_prefix, 1, pubArr.length)
    //    var hashed: Array[Byte] = hash160(pub_with_prefix)

    var hashed: Array[Byte] = hash160(pubArr)
    val hashed_with_prefix: Array[Byte] = new Array[Byte](hashed.length + 1)
    val prefix2: Array[Byte] = Array(0x6f)
    System.arraycopy(prefix2, 0, hashed_with_prefix, 0, 1)
    System.arraycopy(hashed, 0, hashed_with_prefix, 1, hashed.length)
    val checksum: Array[Byte] = hash256(hashed_with_prefix)
    val result: Array[Byte] = new Array[Byte](hashed_with_prefix.length + 4)
    System.arraycopy(hashed_with_prefix, 0, result, 0, hashed_with_prefix.length)
    System.arraycopy(checksum, 0, result, hashed_with_prefix.length, 4)
    return encodeBase58(result)
  }

  def hash160(pubArr: Array[Byte]): Array[Byte] = {
    val r: Array[Byte] = sha256(pubArr)
    val d: RIPEMD160Digest = new RIPEMD160Digest()
    d.update(r, 0, r.length)
    val o: Array[Byte] = new Array[Byte](d.getDigestSize)
    d.doFinal(o, 0)

    return o
  }

  def priToPub(priArr: Array[Byte]): Array[Byte] = {
    val params = ECNamedCurveTable.getParameterSpec("secp256k1")
    val fact = KeyFactory.getInstance("ECDsA", "BC")
    val curve = params.getCurve()
    val ellipticCurve = EC5Util.convertCurve(curve, params.getSeed)
    val point = ECPointUtil.decodePoint(ellipticCurve, priArr)
    val params2 = EC5Util.convertSpec(ellipticCurve, params)
    val keySpec = new ECPublicKeySpec(point, params2)
    var ret: ECPublicKey = fact.generatePublic(keySpec).asInstanceOf[ECPublicKey]
    ret.getEncoded()
  }

  def getKeyPairBytes(): ArrayList[Array[Byte]] = {
    var pri_key: Array[Byte] = generatePrivateKey()
    var pub_key: Array[Byte] = generatePublicKey(pri_key)
    var ret: ArrayList[Array[Byte]] = new ArrayList[Array[Byte]]
    ret.add(pri_key)
    ret.add(pub_key)

    return ret
  }

  def encodeWIF(buf: Array[Byte]): String = {
    var tmp = new Array[Byte](buf.length + 1)
    tmp(0) = Integer.parseUnsignedInt(String.valueOf(0xEF)).asInstanceOf[Byte]
    System.arraycopy(buf, 0, tmp, 1, buf.length)
    var hashed = hash256(tmp)
    var tmp2 = new Array[Byte](buf.length + 4)
    System.arraycopy(buf, 0, tmp2, 0, buf.length)
    System.arraycopy(hashed, 0, tmp2, buf.length, 4)

    return encodeBase58(tmp2)
  }

  def encodeBase58(input: Array[Byte]): String = {
    if (input.length == 0) return ""
    // Count leading zeros.
    var zeros = 0
    while (zeros < input.length && input(zeros) == 0) {
      zeros += 1
    }
    // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
    var tmp = Arrays.copyOf(input, input.length) // since we modify it in-place

    val encoded = new Array[Char](tmp.length * 2)
    // upper bound
    var outputStart = encoded.length
    var inputStart: Int = zeros
    while (inputStart < tmp.length) {
      outputStart -= 1
      encoded(outputStart) = ALPHABET(divmod(input, inputStart, 256, 58))
      if (input(inputStart) == 0) {
        inputStart += 1 // optimization - skip leading zeros
      }
    }
    // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
    while (outputStart < encoded.length && encoded(outputStart) == ENCODED_ZERO) {
      outputStart += 1
    }
    zeros -= 1
    while (zeros >= 0) {
      outputStart -= 1
      encoded(outputStart) = ENCODED_ZERO
      zeros -= 1
    }
    // Return encoded string (including encoded leading zeros).
    new String(encoded, outputStart, encoded.length - outputStart)
  }

  def divmod(number: Array[Byte], firstDigit: Int, base: Int, divisor: Int): Byte = {
    var remainder = 0
    for (i <- firstDigit until number.length) {
      var digit = number(i).asInstanceOf[Int] & 0xFF
      var temp = remainder * base + digit
      number(i) = (temp / divisor).asInstanceOf[Byte]
      remainder = temp % divisor
    }
    remainder.asInstanceOf[Byte]
  }


  def decodeBase58(input: String): Array[Byte] = {
    if (input.length == 0) return new Array[Byte](0)
    // Convert the base58-encoded ASCII chars to a base58 byte sequence (base58 digits).
    val input58 = new Array[Byte](input.length)
    for (i <- 0 until input.length) {
      var c = input.charAt(i)
      var digit = if (c < 128) {
        INDEXES(c)
      } else {
        -1
      }
      if (digit < 0) {
        println("Illegal character " + c + " at position " + i)
        System.exit(0)
      }
      input58(i) = digit.asInstanceOf[Byte]
    }

    // Count leading zeros.
    var zeros = 0
    while (zeros < input58.length && input58(zeros) == 0) zeros += 1

    // Convert base-58 digits to base-256 digits.
    val decoded = new Array[Byte](input.length)
    var outputStart = decoded.length
    var inputStart: Int = zeros
    while (inputStart < input58.length) {
      outputStart -= 1
      decoded(outputStart) = divmod(input58, inputStart, 58, 256)
      if (input58(inputStart) == 0) {
        inputStart += 1 // optimization - skip leading zeros
      }
    }
    // Ignore extra leading zeroes that were added during the calculation.
    while (outputStart < decoded.length && decoded(outputStart) == 0) outputStart += 1
    // Return decoded data (including original number of leading zeros).
    Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length)
  }


  def longToLittleNosin(value: Long): Long = {
    val buf = ByteBuffer.allocate(8)
    buf.putLong(lang.Long.parseUnsignedLong(String.valueOf(value)))
    buf.flip()
    buf.order(ByteOrder.LITTLE_ENDIAN)
    buf.getLong()
  }

  def intToLittleNosin(value: Int): Int = {
    val buf = ByteBuffer.allocate(4)
    buf.putInt(Integer.parseUnsignedInt(String.valueOf(value)))
    buf.flip()
    buf.order(ByteOrder.LITTLE_ENDIAN)
    buf.getInt()
  }

  def shortToLittleNosin(value: Short): Short = {
    val buf = ByteBuffer.allocate(2)
    buf.putShort(Integer.parseUnsignedInt(String.valueOf(value)).asInstanceOf[Short])
    buf.flip()
    buf.order(ByteOrder.LITTLE_ENDIAN)
    buf.getShort()
  }

  def byteToLittleNosin(value: Byte): Byte = {
    val buf = ByteBuffer.allocate(1)
    buf.put(value)
    buf.flip()
    buf.order(ByteOrder.LITTLE_ENDIAN)
    Integer.parseUnsignedInt(String.valueOf(buf.get())).asInstanceOf[Byte]
  }

  def createHeader(msg: Version, data: Array[Byte]): MessageHeader = {
    val header = new MessageHeader
    header.magic = intToLittleNosin(0x0709110B)
    val commandName = "version".toCharArray()
    for (i <- 0 until commandName.length) {
      header.commandName(i) = commandName(i).asInstanceOf[Byte]
    }
    header.payloadSize = intToLittleNosin(msg.bytes)
    val hash = hash256(data)
    header.checksum(0) = hash(0)
    header.checksum(1) = hash(1)
    header.checksum(2) = hash(2)
    header.checksum(3) = hash(3)
    header
  }

  def readHeader(): MessageHeader = {
    val header = new MessageHeader
    din.readInt()
    val commandName = new Array[Byte](12)
    din.read(commandName, 0, 12)
    header.commandName = commandName
    din.read(new Array[Byte](4), 0, 4)
    header
  }

  def readNetAddr(): NetAddr = new NetAddr

  def readVersion(): Version = new Version

  def readVerack(): Verack = new Verack

  def writeHeader(header: MessageHeader): Unit = {
    dout.writeInt(header.magic)
    dout.write(header.commandName, 0, 12)
    dout.writeInt(header.payloadSize)
    dout.write(header.checksum, 0, 4)
  }

  def writeNetAddr(buf: ByteBuffer): Unit = {
    buf.putLong(longToLittleNosin(1))
    for (ip <- Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1)) {
      buf.put(ip.asInstanceOf[Byte])
    }
    buf.putShort(8333)
  }

  def writeVersion(ver: Version): Unit = {
    val buf = ByteBuffer.allocate(86)
    buf.putInt(intToLittleNosin(70015))
    buf.putLong(longToLittleNosin(1))
    buf.putLong(longToLittleNosin((System.currentTimeMillis() / 1000).asInstanceOf[Long]))
    writeNetAddr(buf)
    writeNetAddr(buf)
    buf.putLong(longToLittleNosin(0))
    buf.put(byteToLittleNosin(0))
    buf.putInt(intToLittleNosin(0))
    buf.put(byteToLittleNosin(0))
    val verArr = buf.array()
    writeHeader(createHeader(ver, verArr))
    dout.write(verArr, 0, verArr.length)
  }

  def writeVerack(): Unit = {
    val header = new MessageHeader()
    header.magic = intToLittleNosin(0x0709110B)
    val commandName = "verack".toCharArray()
    for (i <- 0 until commandName.length) {
      header.commandName(i) = commandName(i).asInstanceOf[Byte]
    }
    header.payloadSize = intToLittleNosin(0)
    header.checksum(0) = shortToLittleNosin(0x5d).asInstanceOf[Byte]
    header.checksum(1) = shortToLittleNosin(0xf6).asInstanceOf[Byte]
    header.checksum(2) = shortToLittleNosin(0xe0).asInstanceOf[Byte]
    header.checksum(3) = shortToLittleNosin(0xe2).asInstanceOf[Byte]

    writeHeader(header)
  }

  def encodeInconmpTx(tx: Tx): Array[Byte] = {
    var buf: ByteBuffer = ByteBuffer.allocate(106)
    buf.putInt(intToLittleNosin(tx.version)) //4
    buf.put(tx.txIn(0).previousOutput.hash) //32 fixed
    buf.putInt(intToLittleNosin(tx.txIn(0).previousOutput.index)) //4
    buf.putLong(longToLittleNosin(tx.txOut(0).value)) //8
    buf.put(tx.txOut(0).pkScript.array()) //24
    buf.putLong(longToLittleNosin(tx.txOut(1).value)) //8
    buf.put(tx.txOut(1).pkScript.array()) //22
    buf.putInt(intToLittleNosin(tx.locktime)) //4
    return buf.array()
  }

  def createTx(): Tx ={
    var tx: Tx = new Tx()
    tx.version = 1
    tx.locktime = 0x00

    var outpoint: OutPoint = new OutPoint()
    outpoint.hash = DatatypeConverter.parseHexBinary("1b320ad6e1fd8a2caa5d832d4c8ff5bd72f750f1715a718d3983a366b093a4aa")

    //リバースする
    var tmpList: java.util.List[Byte] = Arrays.asList(outpoint.hash)
    Collections.reverse(tmpList)
    outpoint.hash = tmpList.toArray(new Array[Byte](outpoint.hash.length))

    outpoint.index = 0x00

    var txin: TxIn = new TxIn()
    txin.previousOutput = outpoint
    txin.sequence = 0xFFFFFFFF

    var txout1: TxOut = new TxOut()
    var txout2: TxOut = new TxOut()
    var balance = 8474938958L
    var amount = 1474938958L
    var fee = 10000000L

    var toAddr = "2NA98LJynfmvBXVGPvcfM6MWUbfHvrJLofM"
    var decodedToAddr = decodeAddress(toAddr)
    var decodedFromAddr = decodeAddress(PUBLIC_BTC_ADDRESS)

    var lockingScript1: ByteBuffer = ByteBuffer.allocate(22)
    lockingScript1.put(byteToLittleNosin(OP_HASH160))
    lockingScript1.put(op_pushdata(decodedToAddr))
    lockingScript1.put(byteToLittleNosin(OP_EQUAL))

    var lockingScript2: ByteBuffer = ByteBuffer.allocate(24)
    lockingScript1.put(byteToLittleNosin(OP_DUP))
    lockingScript1.put(byteToLittleNosin(OP_HASH160))
    lockingScript1.put(op_pushdata(decodedFromAddr))
    lockingScript1.put(byteToLittleNosin(OP_EQUALVERIFY))
    lockingScript1.put(byteToLittleNosin(OP_CHECKSIG))

    txout1.value = amount
    txout1.pkScript = lockingScript1

    txout2.value = (balance - amount - fee)
    txout2.pkScript = lockingScript2

    var subscript = "76a9146543e081b512be7267c61bae0040192574ab19f088a"
    txin.signatureScript = DatatypeConverter.parseHexBinary(subscript)
    tx.txIn = Array(txin)
    tx.txOut = Array(txout1, txout2)

    //署名
    var hashType: Byte = 0x01.asInstanceOf[Byte]
    var hashTypeCode: Array[Byte] = Array(0x01, 0x00, 0x00, 0x00)
    var secKey: Array[Byte] = decodeWIF(PUBLIC_BTC_ADDRESS)
    var encoded_tx: Array[Byte] = encodeInconmpTx(tx)
    var beHashed: Array[Byte] = new Array[Byte](106+4)
    Arrays.copyOfRange(encoded_tx, 0, beHashed, 0, encoded_tx.length)
    Arrays.copyOfRange(hashTypeCode, 0, beHashed, encoded_tx.length, hashTypeCode.length)
    var beSigned: Array[Byte] = sha256(beHashed)
    var sign: Array[Byte] = getSign(beSigned, secKey)

    return new Tx()
  }

  def getSign(data: Array[Byte], pri_key: Array[Byte]): Array[Byte] = {
    try {
      Security.addProvider(new BouncyCastleProvider())
      val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
      val ecdsaSigner = new ECDSASigner()
      val domain = new ECDomainParameters(spec.getCurve, spec.getG, spec.getN)
      val privateKeyParms = new ECPrivateKeyParameters(new BigInteger(1, pri_key), domain)
      val params = new ParametersWithRandom(privateKeyParms)
      ecdsaSigner.init(true, params)
      val sig: Array[BigInteger] = ecdsaSigner.generateSignature(data)

      return sig.toByteArray()
    } catch {
      case e: Exception =>
        return null
    }
  }

  def writeTx() = {

  }

  def writeTxIn() = {

  }

  def writeTxOut() = {

  }

  def signTx() = {

  }

  def sendBTCToTestnetFaucet(): Unit = {

  }

  def withBitcoinConnection(): Unit = {
    val ver = new Version()
    writeVersion(ver)
    println("send version")
    var isVersion = false
    var isVerack = false
    while ((!isVersion) || (!isVerack)) {
      val header = readHeader()
      val commandCharacters = new Array[Char](12)
      for (i <- 0 until header.commandName.length) {
        commandCharacters(i) = header.commandName(i).asInstanceOf[Char]
      }
      val cmd = new String(commandCharacters)
      println("recv " + cmd)
      if (cmd == "version") {
        isVersion = true
        val ver = readVersion()
        writeVerack()
      } else if (cmd == "verack") {
        isVerack = true
        val vack = readVerack()
      }
    }
  }

}

object Main {
  def main(args: Array[String]) {
    val messageHandler = new MessageHandler()
    messageHandler.storedKeyCheck()
    //    var tmp: ArrayList[Array[Byte]] = messageHandler.getKeyPairBytes()
    //    println(messageHandler.encodeWIF(tmp.get(0)))
    //    println(messageHandler.encodeBTCAddress(tmp.get(1)))
    //    println(DatatypeConverter.printHexBinary(tmp.get(0)))
    //    println(DatatypeConverter.printHexBinary(tmp.get(1)))

    //messageHandler.withBitcoinConnection()
  }
}
