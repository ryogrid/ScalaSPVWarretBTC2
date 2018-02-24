import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.{lang, util}
import java.net.Socket
import java.security.{KeyPair, KeyPairGenerator, MessageDigest, NoSuchAlgorithmException, SecureRandom}
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Arrays

import scala.collection.JavaConversions._
import java.security.spec.ECGenParameterSpec
import java.security.Security
import javax.xml.bind.DatatypeConverter

import scala.util.control.Breaks

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
  var startHeight:Int = 0,
  var relay: Boolean = false,
  var bytes: Int = 86
)

class Verack(var commandName: String = "verack")

class OutPoint (
  var hash: Array[Byte] = new Array[Byte](32),
  var index: Int = 0
               )

class TxIn (
  var previousOutput: OutPoint = null,
  var signatureScript: StringBuffer = null,
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
  var pkScript: StringBuffer = null
           )

class MessageHandler(dummy:String = "dummy") {
  val client: Socket = new Socket("testnet-seed.bitcoin.jonasschnelli.ch", 18333)
  val din: DataInputStream = new DataInputStream(client.getInputStream())
  var dout: DataOutputStream = new DataOutputStream(client.getOutputStream())
  val ALPHABET: Array[Char] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray()
  val ENCODED_ZERO = ALPHABET(0)
  var INDEXES: Array[Int] = new Array[Int](128)

  def this(){
    this("dummy")
    Arrays.fill(INDEXES, -1)
    for(i <- 0 until ALPHABET.length){
      INDEXES(ALPHABET(i)) = i
    }
  }

  def sha256(payload: Array[Byte]): Array[Byte] = {
    val md = MessageDigest.getInstance("SHA-256")
    md.update(payload)
    md.digest()
  }

  def hash256(payload: Array[Byte]): Array[Byte] = {
    sha256(sha256(payload))
  }

  def genSecKey(): KeyPair ={
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider)
    val keyGen = KeyPairGenerator.getInstance("ECDsA", "BC")
    val ecSpec = new ECGenParameterSpec("secp256k1")
    keyGen.initialize(ecSpec, new SecureRandom())
    keyGen.generateKeyPair()
  }

  def encodeWIF(buf: Array[Byte]): String = {
    var tmp = new Array[Byte](buf.length + 1)
    tmp(0) = Integer.parseUnsignedInt(String.valueOf(0xEF)).asInstanceOf[Byte]
    System.arraycopy(tmp, 1, buf, 0, buf.length)
    var hashed = hash256(tmp)
    var tmp2 = new Array[Byte](tmp.length + 4)
    System.arraycopy(tmp2, 0, tmp, 0, tmp.length)
    System.arraycopy(tmp2, tmp.length, hashed, 0, 4)

    return encodeBase58(tmp2)
  }


  def encodeBase58(input: Array[Byte]): String = {
    if (input.length == 0) return ""
    // Count leading zeros.
    var zeros = 0
    while (zeros < input.length && input(zeros) == 0){
      zeros += 1
    }
    // Convert base-256 digits to base-58 digits (plus conversion to ASCII characters)
    var tmp = Arrays.copyOf(input, input.length) // since we modify it in-place

    val encoded = new Array[Char](tmp.length * 2)
    // upper bound
    var outputStart = encoded.length
    var inputStart:Int = zeros
    while(inputStart < tmp.length){
      outputStart -= 1
      encoded(outputStart) = ALPHABET(divmod(input, inputStart, 256, 58))
      if (input(inputStart) == 0){
        inputStart += 1 // optimization - skip leading zeros
      }
    }
    // Preserve exactly as many leading encoded zeros in output as there were leading zeros in input.
    while (outputStart < encoded.length && encoded(outputStart) == ENCODED_ZERO){
      outputStart += 1
    }
    zeros -= 1
    while (zeros >= 0){
      outputStart -= 1
      encoded(outputStart) = ENCODED_ZERO
    }
    // Return encoded string (including encoded leading zeros).
    new String(encoded, outputStart, encoded.length - outputStart)
  }

  def divmod(number: Array[Byte], firstDigit: Int, base: Int, divisor: Int): Byte = {
    var remainder = 0
    for(i <- firstDigit until number.length) {
      val digit = number(i).asInstanceOf[Int] & 0xFF
      val temp = remainder * base + digit
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
      var digit = if (c < 128){
        INDEXES(c)
      } else {
        -1
      }
      if (digit < 0){
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
    var inputStart:Int = zeros
    while(inputStart < input58.length){
      outputStart -= 1
      decoded(outputStart) = divmod(input58, inputStart, 58, 256)
      if (input58(inputStart) == 0){
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
    for(ip <- Array(0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1)){
      buf.put(ip.asInstanceOf[Byte])
    }
    buf.putShort(8333)
  }

  def writeVersion(ver: Version): Unit = {
    val buf = ByteBuffer.allocate(86)
    buf.putInt(intToLittleNosin(70015))
    buf.putLong(longToLittleNosin(1))
    buf.putLong(longToLittleNosin((System.currentTimeMillis()/1000).asInstanceOf[Long]))
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

  def withBitcoinConnection(): Unit = {
    val ver = new Version()
    writeVersion(ver)
    println("send version")
    var isVersion = false
    var isVerack = false
    while((!isVersion) || (!isVerack)){
      val header = readHeader()
      val commandCharacters = new Array[Char](12)
      for(i <- 0 until header.commandName.length){
        commandCharacters(i) = header.commandName(i).asInstanceOf[Char]
      }
      val cmd = new String(commandCharacters)
      println("recv " + cmd)
      if(cmd == "version") {
        isVersion = true
        val ver = readVersion()
        writeVerack()
      }else if(cmd == "verack"){
        isVerack = true
        val vack = readVerack()
      }
    }
  }

}

object Main{
  def main(args: Array[String]) {
    val messageHandler = new MessageHandler()
    val kpair = messageHandler.genSecKey()
    println(messageHandler.encodeBase58(kpair.getPrivate().getEncoded()))

    messageHandler.withBitcoinConnection()
  }
}
