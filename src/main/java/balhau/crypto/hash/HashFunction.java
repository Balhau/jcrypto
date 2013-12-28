/**
 * No pacote balhau.crypto.hash encontramos implementadas funções de Hash
 */
package balhau.crypto.hash;
import balhau.utils.Mask;

/**
 * Esta é a classe base de todas as funções Hash
 * @author balhau
 *
 */
public abstract class HashFunction {
	protected String _h(int v){
		return Integer.toHexString(v);
	}
	
	protected String _h(long v){
		return Long.toHexString(v);
	}
	
	protected byte[] long32ToByte(long l32){
		byte[] out=new byte[4];
		out[0]=(byte)((l32>>24)&Mask.MASK8);out[1]=(byte)((l32>>16)&Mask.MASK8);
		out[2]=(byte)((l32>>8)&Mask.MASK8);out[3]=(byte)(l32&Mask.MASK8);
		return out;
	}
	/**
	 * Método que transforma um inteiro de 32 bits para um array de valores de 8 bits
	 * @param i32 {@link int} Número de 32 bits
	 * @return {@link char[]} Array com quatro elementos de 8 bits
	 */
	protected byte[] int32ToByte(int i32){
		byte[] out=new byte[4];
		out[0]=(byte)((i32>>24)&Mask.MASK8);out[1]=(byte)((i32>>16)&Mask.MASK8);
		out[2]=(byte)((i32>>8)&Mask.MASK8);out[3]=(byte)(i32&Mask.MASK8);
		return out;
	}
	/**
	 * Método que converte um array de 4 inteiros de 8 bits para um inteiro de 32 bits
	 * @param arr {@link char[]} Array de valores 8 bits
	 * @return {@link int} Inteiro de 32 bits
	 */
	protected int char2int32(char[] arr){
		int out;
		out=(arr[3]<<24)|(arr[2]<<16)|(arr[1]<<8)|(arr[0]);
		return out;
	}
	/**
	 * Converte um bloco de 64 elementos de 8 bits para um bloco de 16 elementos de 32 bits
	 * @param block {@link char[]} Bloco de 64 elementos de 8 bits
	 * @return {@link int[]} Bloco de 16 elemntos de 32 bits
	 */
	protected int[] block64Char2block16Int(char[] block){
		int[] bl=new int[16];
		int j=0;
		for(int i=0;i<64;i+=4){
			bl[j]=(int)((((long)block[i])<<24)|(((long)block[i+1])<<16)|(((long)block[i+2])<<8)|(((long)block[i+3]))&Mask.MASK32);
			j++;
		}
		return bl;
	}
	/**
	 * Converte um block de 64 elementos de 8 bits para um bloco de 16 elementos de 32 bits com reversão de ordem.
	 * @param block {@link char[]} Block de 64 elementos de 8 bits
	 * @return {@link int[]} Bloco de 16 elementos de 32 bits
	 */
	protected int[] block64Byte2block16IntRev(byte[] block){
		int[] bl=new int[16];
		int j=0;
		for(int i=0;i<64;i+=4){
			bl[j]=	(int)(
					((((long)block[i+3])<<24)	&0xFF000000)|
				    ((((long)block[i+2])<<16)	&0x00FF0000)|
				    ((((long)block[i+1])<<8)	&0x0000FF00)|
				    (((long)block[i])			&0x000000FF));
			j++;
		}
		return bl;
	}
}
