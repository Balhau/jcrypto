package balhau.crypto.test.groovy;

import static org.junit.Assert.*;

import balhau.crypto.hmac.HMAC
import org.junit.Test;
import balhau.crypto.hash.HashType;
import balhau.crypto.hash.MD5;
import balhau.crypto.hash.Ripmed160;
import balhau.utils.ArrayUtils;

/**
 * Groovy test suit. In the future all test suits should be done in groovy
 * @author balhau
 *
 */
class CryptoTestSuit {

	@Test
	def void HMAC_MD5() {
		def hm1=new HMAC("what do ya want for nothing?", "Jefe".getBytes(), HashType.MD5)
		assertTrue hm1.encode().equals("750c783e6ab0b503eaa86e310a5db738")
		hm1=new HMAC("Hi There",ArrayUtils.repeatByte((byte)0x0b, 16),HashType.MD5)
 		assertTrue hm1.encode().equals("9294727a3638bb1c13f48ef8158bfc9d")
	}
	
	@Test void HMAC_SHA1(){
		def byte[] key=[
			0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
			0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
			0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
			0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
		]
		
		def hm=new HMAC("Sample #1", key, HashType.SHA1);
		assertTrue hm.encode().equals("4f4ca3d5d68ba7cc0a1208c9c61e9c5da0403c0a")
		
		key=[0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,
			 0x3c,0x3d,0x3e,0x3f,0x40,0x41,0x42,0x43
		];
		hm=new HMAC("Sample #2", key, HashType.SHA1);
		assertTrue(hm.encode().equals("0922d3405faa3d194f82a45830737d5cc6c75d24"));
	}
	
	@Test
	def void ripmed160(){
		def rp=new Ripmed160()
		rp.update("".getBytes())
		rp.finish()
		rp.hexDigest()
		assertTrue(true)
	}
	
	@Test
	def void md5(){
		def md=new MD5();
		String hex=md.encode("Hello World!");
		assertTrue(hex.equals("ed076287532e86365e841e92bfc50d8c"));
	}
}
