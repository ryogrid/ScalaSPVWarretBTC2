import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.Socket
import java.security.{KeyPairGenerator, MessageDigest, NoSuchAlgorithmException, SecureRandom, KeyPair}
import java.nio.ByteBuffer
import java.nio.ByteOrder

import scala.collection.JavaConversions._
import java.security.spec.ECGenParameterSpec
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

  def longToLittleNosin(value: Long): Long = {
    val buf = ByteBuffer.allocate(8)
    buf.putLong(java.lang.Long.parseUnsignedLong(String.valueOf(value)))
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
    //println(kpair.getPrivate().toString())

    messageHandler.withBitcoinConnection()
  }
}
