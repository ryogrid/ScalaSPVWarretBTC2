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

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequenceGenerator
import java.io.ByteArrayOutputStream
import java.io.IOException

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import java.security.PrivateKey

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner

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
             var pkScript: Array[Byte] = null
           )

class Inv(
           var inv_count: Int = 0,
           var inventory: Array[Inventory] = null
         )

class Inventory(
                 var invType: Int = 0,
                 var hash: Array[Byte] = new Array[Byte](32)
               )

class GetData(
               var inv_num: Int = 0,
               var inventory: Array[Inventory] = null,
               var commandName: String = "getdata"
             )


class MessageHandler(dummy: String = "dummy") {
  //val client: Socket = null
  var client: Socket = null
  //val din: DataInputStream = null
  var din: DataInputStream = null
  //var dout: DataOutputStream = null
  var dout: DataOutputStream = null
  val ALPHABET: Array[Char] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray()
  val ENCODED_ZERO = ALPHABET(0)
  var INDEXES: Array[Int] = new Array[Int](128)
  val RANDOM_NUMBER_ALGORITHM = "SHA1PRNG"
  val RANDOM_NUMBER_ALGORITHM_PROVIDER = "SUN"
  val PRIVATE_PATH = "./privateWIF.key"
  val PUBLIC_PATH = "./publicBTCAddress.key"
  var PRIVATE_KEY_WIF: String = null
  var PUBLIC_BTC_ADDRESS: String = null
  var PUBLIC_KEY: String = null

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

  def init_conn() = {
    client = new Socket("testnet-seed.bitcoin.jonasschnelli.ch", 18333)
    din = new DataInputStream(client.getInputStream())
    dout = new DataOutputStream(client.getOutputStream())
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
      PUBLIC_KEY = DatatypeConverter.printHexBinary(generatePublicKey(decodeWIF(PRIVATE_KEY_WIF)))
      println("keys stored:")
    } else {
      var pairs: ArrayList[Array[Byte]] = getKeyPairBytes()
      PRIVATE_KEY_WIF = encodeWIF(pairs.get(0))
      PUBLIC_BTC_ADDRESS = encodeBTCAddress((pairs.get(1)))
      PUBLIC_KEY = DatatypeConverter.printHexBinary(generatePublicKey(decodeWIF(PRIVATE_KEY_WIF)))
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
    privateKeyCheck = new BigInteger(privateKeyAttempt)
    while ((privateKeyCheck.compareTo(BigInteger.ZERO) == 0) || (privateKeyCheck.compareTo(maxKey) == 1)) {
      secureRandom.nextBytes(privateKeyAttempt)
      privateKeyCheck = new BigInteger(privateKeyAttempt)
    }
    privateKeyAttempt
  }

  def generatePublicKey(privateKey: Array[Byte]): Array[Byte] = try {
    val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val pointQ = spec.getG.multiply(new BigInteger(privateKey))
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

  def encodeWIF(buf: Array[Byte]): String = {
    var tmp = new Array[Byte](buf.length + 1)
    tmp(0) = Integer.parseUnsignedInt(String.valueOf(0xEF)).asInstanceOf[Byte]
    System.arraycopy(buf, 0, tmp, 1, buf.length)
    var hashed = hash256(tmp)
    var tmp2 = new Array[Byte](tmp.length + 4)
    System.arraycopy(tmp, 0, tmp2, 0, tmp.length)
    System.arraycopy(hashed, 0, tmp2, tmp.length, 4)

    return encodeBase58(tmp2)
  }

  def decodeWIF(str: String): Array[Byte] = {
    var decoded: Array[Byte] = decodeBase58(str)
    return Arrays.copyOfRange(decoded, 1, decoded.length - 4)
    //return Arrays.copyOfRange(decoded, 0, decoded.length - 4)
  }

  def decodeAddress(str: String): Array[Byte] = {
    return decodeWIF(str)
  }

  def encodeBTCAddress(pubArr: Array[Byte]): String = {
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

//  def intToBig(value: Array[Byte]): Int = {
//    val buf = ByteBuffer.allocate(4)
//    //buf.putInt(Integer.parseInt(String.valueOf(value)))
//    buf.put(value)
//    //buf.flip()
//    buf.order(ByteOrder.LITTLE_ENDIAN)
//    Integer.parseUnsignedInt(String.valueOf(buf.getInt()))
//
////    val hex = Integer.toHexString(buf.getInt())
////    return Integer.valueOf(hex.toString, 16)
//  }

  def intToBig(value: Int): Int = {
    val buf = ByteBuffer.allocate(4)
    buf.putInt(value)
    buf.flip()
    buf.order(ByteOrder.LITTLE_ENDIAN)
    Integer.parseUnsignedInt(String.valueOf(buf.getInt()))

    //    val hex = Integer.toHexString(buf.getInt())
    //    return Integer.valueOf(hex.toString, 16)
  }

  def byteToBig(value: Byte): Byte = {
    val buf = ByteBuffer.allocate(1)
    buf.put(value)
    Integer.parseUnsignedInt(String.valueOf(value)).asInstanceOf[Byte]
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
    //buf.flip()
    //buf.order(ByteOrder.LITTLE_ENDIAN)
    //Integer.parseUnsignedInt(String.valueOf(buf.get())).asInstanceOf[Byte]
    Integer.parseUnsignedInt(String.valueOf(value)).asInstanceOf[Byte]
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
    val header = new MessageHeader()
    din.readInt()
    val commandName = new Array[Byte](12)
    din.read(commandName, 0, 12)
    header.commandName = commandName
    //var tmp_buf: Array[Byte] = new Array[Byte](4)
    //din.read(tmp_buf, 0, 4)
    header.payloadSize = intToBig(din.readInt())
    //header.payloadSize = intToBig(tmp_buf)

    din.read(new Array[Byte](4), 0, 4)
    header
  }

  def readInventory(): Inventory = {
    var inv: Inventory = new Inventory()
    inv.invType = intToBig(din.readInt())
    var buf: Array[Byte] = new Array[Byte](32)
    din.read(buf, 0, 32)
    inv.hash = buf
    inv
  }

  def readGetData(): GetData = {
    var gdata = new GetData()
    var inv_num: Byte = byteToBig(din.readByte())
    gdata.inv_num = inv_num
    var inv_arr: Array[Inventory] = new Array[Inventory](inv_num)
    for(i <- 0 until inv_num){
      inv_arr(i) = readInventory()
    }
    gdata.inventory = inv_arr
    gdata
  }

  def readNetAddr(): NetAddr = new NetAddr

  def readVersion(): Version = {
    return new Version()
  }

  def readVerack(): Verack = {
    return new Verack()
  }

  def writeHeader(header: MessageHeader): Unit = {
    dout.writeInt(header.magic)
    dout.write(header.commandName, 0, 12)
    dout.writeInt(header.payloadSize)
    dout.write(header.checksum, 0, 4)
  }

  def writeNetAddr(buf: ByteBuffer): Unit = {
    buf.putLong(longToLittleNosin(1)) //8
    for (ip <- Array(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1)) {
      buf.put(ip.asInstanceOf[Byte]) //16
    }
    buf.putShort(8333) //2
  }

  def writeVersion(ver: Version): Unit = {
    val buf = ByteBuffer.allocate(86)
    buf.putInt(intToLittleNosin(70015)) //4
    buf.putLong(longToLittleNosin(1)) //8
    buf.putLong(longToLittleNosin((System.currentTimeMillis() / 1000).asInstanceOf[Long])) //8
    writeNetAddr(buf) //26
    writeNetAddr(buf) //26
    buf.putLong(longToLittleNosin(0)) //8
    buf.put(byteToLittleNosin(0)) //1
    buf.putInt(intToLittleNosin(0)) //4
    buf.put(byteToLittleNosin(0)) //1
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
    header.checksum(0) = 0x5d.asInstanceOf[Byte]
    header.checksum(1) = 0xf6.asInstanceOf[Byte]
    header.checksum(2) = 0xe0.asInstanceOf[Byte]
    header.checksum(3) = 0xe2.asInstanceOf[Byte]

    writeHeader(header)
  }

  def encodeInconmpTx(tx: Tx): Array[Byte] = {
    var buf: ByteBuffer = ByteBuffer.allocate(106)
    buf.putInt(intToLittleNosin(tx.version)) //4
    buf.put(tx.txIn(0).previousOutput.hash) //32 fixed
    buf.putInt(intToLittleNosin(tx.txIn(0).previousOutput.index)) //4
    buf.putLong(longToLittleNosin(tx.txOut(0).value)) //8
    buf.put(tx.txOut(0).pkScript) //24
    buf.putLong(longToLittleNosin(tx.txOut(1).value)) //8
    buf.put(tx.txOut(1).pkScript) //22
    buf.putInt(intToLittleNosin(tx.locktime)) //4
    return buf.array()
  }

  def encodeTx(tx: Tx): Array[Byte] = {
    var buf: ByteBuffer = ByteBuffer.allocate(106 + tx.txIn(0).signatureScript.length)
    buf.putInt(intToLittleNosin(tx.version)) //4
    buf.put(tx.txIn(0).previousOutput.hash) //32 fixed
    buf.putInt(intToLittleNosin(tx.txIn(0).previousOutput.index)) //4
    buf.put(tx.txIn(0).signatureScript)
    buf.putLong(longToLittleNosin(tx.txOut(0).value)) //8
    buf.put(tx.txOut(0).pkScript) //24
    buf.putLong(longToLittleNosin(tx.txOut(1).value)) //8
    buf.put(tx.txOut(1).pkScript) //22
    buf.putInt(intToLittleNosin(tx.locktime)) //4
    return buf.array()
  }

  def genTxId(tx: Tx): Array[Byte] ={
    var data: Array[Byte] = encodeTx(tx)
    return hash256(data)
  }

  def createTx(): Tx ={
    var tx: Tx = new Tx()
    tx.version = 1
    tx.locktime = 0x00

    var outpoint: OutPoint = new OutPoint()
    outpoint.hash = DatatypeConverter.parseHexBinary("1b320ad6e1fd8a2caa5d832d4c8ff5bd72f750f1715a718d3983a366b093a4aa")

    //リバースする
    var tmpArr: Array[Byte] = new Array[Byte](32)
    for (i <- 0 until tmpArr.length) {
      tmpArr(i) = outpoint.hash(tmpArr.length - i - 1)
    }
    outpoint.hash = tmpArr

    outpoint.index = 0x00

    var txin: TxIn = new TxIn()
    txin.previousOutput = outpoint
    txin.sequence = 0xFFFFFFFF

    var txout1: TxOut = new TxOut()
    var txout2: TxOut = new TxOut()
    var balance = 130000000L
    var amount = 10000000L
    var fee = 1000000L

    var toAddr = "2NA98LJynfmvBXVGPvcfM6MWUbfHvrJLofM"
    var decodedToAddr = decodeAddress(toAddr)
    var decodedFromAddr = decodeAddress(PUBLIC_BTC_ADDRESS)

    var lockingScript1: ByteBuffer = ByteBuffer.allocate(2 + decodedToAddr.length)
    lockingScript1.put(OP_HASH160)
    lockingScript1.put(op_pushdata(decodedToAddr))
    lockingScript1.put(OP_EQUAL)

    var lockingScript2: ByteBuffer = ByteBuffer.allocate(4 + decodedFromAddr.length)
    lockingScript2.put(OP_DUP)
    lockingScript2.put(OP_HASH160)
    lockingScript2.put(op_pushdata(decodedFromAddr))
    lockingScript2.put(OP_EQUALVERIFY)
    lockingScript2.put(OP_CHECKSIG)

    txout1.value = amount
    txout1.pkScript = lockingScript1.array()

    txout2.value = (balance - amount - fee)
    txout2.pkScript = lockingScript2.array()

    var subscript = "076a9146543e081b512be7267c61bae0040192574ab19f088a"
    txin.signatureScript = DatatypeConverter.parseHexBinary(subscript)
    tx.txIn = Array(txin)
    tx.txOut = Array(txout1, txout2)

    //署名
    var hashType: Byte = 0x01.asInstanceOf[Byte]
    var hashTypeCode: Array[Byte] = Array(0x01, 0x00, 0x00, 0x00)
    var secKey: Array[Byte] = decodeWIF(PRIVATE_KEY_WIF)
    var encoded_tx: Array[Byte] = encodeInconmpTx(tx)
    var beHashed: Array[Byte] = new Array[Byte](encoded_tx.length+hashTypeCode.length)
    System.arraycopy(encoded_tx, 0, beHashed, 0, encoded_tx.length)
    System.arraycopy(hashTypeCode, 0, beHashed, encoded_tx.length, hashTypeCode.length)
    var beSigned: Array[Byte] = hash256(beHashed)
    var sign: Array[Byte] = getSign(beSigned, secKey)
    println(sign.length)
    //println(DatatypeConverter.printHexBinary(sign))

    var pubKey:Array[Byte] = DatatypeConverter.parseHexBinary(PUBLIC_KEY)
    var lockingScript3: ByteBuffer = ByteBuffer.allocate(sign.length + pubKey.length + 1)
    lockingScript3.put(op_pushdata(sign))
    lockingScript3.put(hashType)
    lockingScript3.put(op_pushdata(pubKey))

    txin.signatureScript = lockingScript3.array()

    return tx
  }

  def toCanonicalS(s: BigInteger): BigInteger = {
    val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val HALF_CURVE_ORDER: BigInteger = spec.getN.shiftRight(1)
    if (s.compareTo(HALF_CURVE_ORDER) <= 0){
      s
    } else {
      spec.getN.subtract(s)
    }
  }


  def verify(pub: Array[Byte], data: Array[Byte], rs: Array[BigInteger]): Boolean = {
    val signer = new ECDSASigner
    val params = ECNamedCurveTable.getParameterSpec("secp256k1")
    val ecParams = new ECDomainParameters(params.getCurve, params.getG, params.getN, params.getH)
    val pubKeyParams = new ECPublicKeyParameters(ecParams.getCurve.decodePoint(pub), ecParams)
    signer.init(false, pubKeyParams)
    signer.verifySignature(data, rs(0).abs, rs(1).abs)
  }

  def getSignAndGetRS(priv: Array[Byte], data: Array[Byte]): Array[BigInteger] = {
    val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
    val ecParams = new ECDomainParameters(spec.getCurve, spec.getG, spec.getN, spec.getH)
    val signer = new ECDSASigner()
    val privKey = new ECPrivateKeyParameters(new BigInteger(priv), ecParams)
    val params = new ParametersWithRandom(privKey)
    signer.init(true, params)
    val sigs = signer.generateSignature(data)
    sigs
  }

  // TODO: should be 70 bytes but tamani 72 bytes de dame
  def getSign(data: Array[Byte], pri_key: Array[Byte]): Array[Byte] = {
    try {
      Security.addProvider(new BouncyCastleProvider())
      val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
      val ecdsaSigner = new ECDSASigner()
      val domain = new ECDomainParameters(spec.getCurve, spec.getG, spec.getN)
      val privateKeyParms = new ECPrivateKeyParameters(new BigInteger(pri_key), domain)
      val params = new ParametersWithRandom(privateKeyParms)
      ecdsaSigner.init(true, params)

//      val sigData = new LinkedList[Array[Byte]]()
//      val pub_key = generatePublicKey(pri_key)
      val sig = ecdsaSigner.generateSignature(data)
//      val recoveryId = getRecoveryId(sig(0).toByteArray, sig(1).toByteArray, data, publicKey)
      val s = new ByteArrayOutputStream()
      try {
        val seq = new DERSequenceGenerator(s)
        val s0 = sig(0).abs()
        val s1 = sig(1).abs()
        //s.write(s0.toByteArray())
        //s.write(s1.toByteArray())
        seq.addObject(new ASN1Integer(s0))
        seq.addObject(new ASN1Integer(s1))
        //seq.addObject(new ASN1Integer(toCanonicalS(s1)))
        seq.close()

        return s.toByteArray()
      } catch {
        case e: Exception =>
          println(e)
      }
    }catch{
      case e: Exception =>
        println(e)
    }

    return null
  }

  def writeTx(tx: Tx) = {
    var data: Array[Byte] = encodeTx(tx)

    val header = new MessageHeader()
    header.magic = intToLittleNosin(0x0709110B)
    val commandName = "getdata".toCharArray()
    for (i <- 0 until commandName.length) {
      header.commandName(i) = commandName(i).asInstanceOf[Byte]
    }

    var checksum = hash256(data)

    header.payloadSize = intToLittleNosin(data.length)
    header.checksum(0) = checksum(0)
    header.checksum(1) = checksum(1)
    header.checksum(2) = checksum(2)
    header.checksum(3) = checksum(3)

    writeHeader(header)

    dout.write(data, 0, data.length)
  }

  def writeInv(inv: Inv) = {
    val header = new MessageHeader()
    header.magic = intToLittleNosin(0x0709110B)
    val commandName = "inv".toCharArray()
    for (i <- 0 until commandName.length) {
      header.commandName(i) = commandName(i).asInstanceOf[Byte]
    }

    var buf: ByteBuffer = ByteBuffer.allocate(32 + 4 + 1)
    buf.put(1.asInstanceOf[Byte]) // num of Inventory //1
    buf.putInt(intToLittleNosin(inv.inventory(0).invType)) //4
    buf.put(inv.inventory(0).hash) //32
    var checksum = hash256(buf.array())

    header.payloadSize = intToLittleNosin(37) //なぜかここでも変換かけないとダメ
    header.checksum(0) = checksum(0)
    header.checksum(1) = checksum(1)
    header.checksum(2) = checksum(2)
    header.checksum(3) = checksum(3)

    writeHeader(header)

    dout.writeByte(1)
    dout.writeInt(intToLittleNosin(inv.inventory(0).invType))
    dout.write(inv.inventory(0).hash)
    dout.flush()
  }

  def sendBTCToTestnetFaucet(): Unit = {
    var tx: Tx = createTx()
    var txid: Array[Byte] = genTxId(tx)
    var inv: Inv = new Inv()
    var inventory: Inventory = new Inventory()
    inventory.invType = INV_MSG_TX
    inventory.hash = txid
    inv.inventory = Array(inventory)

    println("send inv")
    writeInv(inv)

    var null_buf: Array[Byte] = new Array[Byte](10000)
    while (true) {
      val header = readHeader()
      val commandCharacters = new Array[Char](12)
      for (i <- 0 until header.commandName.length) {
        commandCharacters(i) = header.commandName(i).asInstanceOf[Char]
      }
      val cmd = new String(commandCharacters)
      println("recv " + cmd + " " + header.payloadSize.toString())
      if (cmd.contains("getdata")) {
        var gdata: GetData = readGetData()
        var inv: Inventory = null
        for(i <- 0 until gdata.inv_num){
          if(gdata.inventory(i).invType == INV_MSG_TX && gdata.inventory(i).hash.deep == txid.deep){
            inv = gdata.inventory(i)
          }
        }
        if(inv != null){
          println("send tx")
          writeTx(tx)
        }
      }else{
        din.read(null_buf, 0, header.payloadSize)
      }
    }

  }

  def withBitcoinConnection(): Unit = {
    val ver = new Version()
    writeVersion(ver)
    println("send version")
    var isVersion = false
    var isVerack = false
    var null_buf: Array[Byte] = new Array[Byte](10000)
    while ((!isVersion) || (!isVerack)) {
      val header = readHeader()
      val commandCharacters = new Array[Char](12)
      for (i <- 0 until header.commandName.length) {
        commandCharacters(i) = header.commandName(i).asInstanceOf[Char]
      }
      val cmd = new String(commandCharacters)
      println("recv " + cmd + " " + header.payloadSize.toString())
      if (cmd.contains("version")) {
        isVersion = true
        val ver = readVersion()
        din.read(null_buf, 0, header.payloadSize)
        println("send verack")
        writeVerack()
      } else if (cmd.contains("verack")) {
        isVerack = true
        val vack = readVerack()
        din.read(null_buf, 0, header.payloadSize)
      } else {
        din.read(null_buf, 0, header.payloadSize)
      }
    }
  }

}

object Main {
  def main(args: Array[String]) {
    val messageHandler = new MessageHandler()
    //messageHandler.init_conn()
    messageHandler.storedKeyCheck()
    //println(DatatypeConverter.printHexBinary(messageHandler.decodeWIF(messageHandler.PRIVATE_KEY_WIF)))
    val sig = messageHandler.getSign(messageHandler.hash256("abcd".getBytes()),messageHandler.decodeWIF(messageHandler.PRIVATE_KEY_WIF))
    println(sig.length)
    val rs = messageHandler.getSignAndGetRS(messageHandler.decodeWIF(messageHandler.PRIVATE_KEY_WIF), messageHandler.hash256("abcd".getBytes()))
    //val rs:Array[BigInteger] = Array(new BigInteger(1, Arrays.copyOfRange(sig, 0, 35)), new BigInteger(1, Arrays.copyOfRange(sig, 35, 70)))

    //println(messageHandler.decodeWIF(messageHandler.PRIVATE_KEY_WIF).length)
    println(messageHandler.verify(messageHandler.generatePublicKey(messageHandler.decodeWIF(messageHandler.PRIVATE_KEY_WIF)), messageHandler.hash256("abcd".getBytes()), rs))
    val pub = DatatypeConverter.parseHexBinary(messageHandler.PUBLIC_KEY)
    //println(pub.length)

    //    var tmp: ArrayList[Array[Byte]] = messageHandler.getKeyPairBytes()
    //    println(messageHandler.encodeWIF(tmp.get(0)))
    //    println(messageHandler.encodeBTCAddress(tmp.get(1)))
    //    println(DatatypeConverter.printHexBinary(tmp.get(0)))
    //    println(DatatypeConverter.printHexBinary(tmp.get(1)))

//    messageHandler.withBitcoinConnection()
//    messageHandler.sendBTCToTestnetFaucet()
  }
}
