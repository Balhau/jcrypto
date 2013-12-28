package balhau.crypto.hash;
import balhau.utils.Mask;
/**
 * Classe abstracta com um conjunto de funcionalidades comum a todos os algoritmos SHA
 * @author balhau
 *
 */
public abstract class SHA extends HashFunction {
	protected int[] BUFFER;
	
	protected long[] BUFFERL;
	/**
	 * Constantes para os algoritmos de SHA1 e SHA256
	 * primos 
	 */
	protected int[] tkonst;
	/**
	 * COnstantes para os algoritmos de SHA384 e SHA512
	 */
	protected long[] tkonstl;
	
	/**
	 * Vector de padding
	 */
	protected byte[] padding;
	/**
	 * Buffer de inteiros
	 */
	protected int[] buffMSG;
	
	protected long[] buffMSGL;
	/**
	 * Buffer de caracters
	 */
	protected byte[] chBuff;
	/**
	 * INteiro representando o numero de bytes lidos
	 */
	protected long pos;
	/***
	 * Método para conversão de um bloco de caracteres num inteiro de 32 bits
	 * @param block {@link char[]} Array de caracteres 
	 */
	protected void blockByteToInt(byte[] block){
		int j=0;
		for(int i=0;i<64;i+=4){
			buffMSG[j]=(int)(
					((((long)block[i])<<24)		&0xFF000000)|
					((((long)block[i+1])<<16)	&0x00FF0000)|
					((((long)block[i+2])<<8)	&0x0000FF00)|
					(((long)block[i+3]))		&0x000000FF);
			j++;
		}
	}
	
	protected void blockByteToLong(byte[] block){
		for(int j=0,i=0;i<128;i+=8,j++){
			buffMSGL[j]=(long)((((long)block[i])<<56)+(((long)block[i+1])<<48)+(((long)block[i+2])<<40)+(((long)block[i+3])<<32)+(((long)block[i+4])<<24)
					+(((long)block[i+5])<<16)+(((long)block[i+6])<<8)+((long)block[i+7]));
		}
	}
	
	/**
	 * Efectua a construção do array que contém informação acerca do padding da mensagem
	 */
	protected void buildPadding(){
		buildPadding(64);
	}
	
	protected void buildPadding(int n){
		padding=new byte[n];
		for(int i=0;i<n;i++){
			if(i==0)
				padding[i]=(byte)0x80;
			else
				padding[i]=0;
		}
	}
}
