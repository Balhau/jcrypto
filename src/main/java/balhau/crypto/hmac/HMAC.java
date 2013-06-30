/**
 * O pacote HMAC tem como objectivo implementar a funcionalidade hash message authentication code
 */
package balhau.crypto.hmac;
import balhau.utils.Mask;
import balhau.crypto.hash.HashType;
import balhau.crypto.hash.IHash;
import balhau.utils.ArrayUtils;

/**
 * Classe que implementa a funcionalidade Hash Message Authentication Code (HMAC)
 * A criação deste mecanismo foi baseada no documento
 * "The Keyed-Hash Message Authentication Code". 
 * Este foi criado por
 * Informational Technology Laboratory (ITL)
 * National Institute of Standards and Technology (NIST)
 * E publicado pelo
 * Federal Information Processing Standards (FIPS)
 * É ainda de interesse o documento RFC 2104
 * 
 * A presente classe tem como principal objectivo fornecer um mecanismo de criação de chaves de autenticação com recurso
 * a funções de hash criptográficas.
 * Os códigos HMAC tem como objectivo a verificação da autenticidade da origem de uma determinada mensagem ao mesmo tempo
 * que garantem a sua integridade
 * @author balhau
 *
 */
public class HMAC {
	private static int innerPad=0x36;
	private static int outerPad=0x5c;
	private byte[] key;
	private HashType hashType;
	private String message;
	private byte[] outerP;
	private byte[] innerP;
	/**
	 * Construtor do objecto
	 * @param message {@link String} representando o texto a codificar
	 * @param hashType {@link HashType} representando o tipo de função hash a aplicar na codificação
	 */
	public HMAC(String message,String key,HashType hashType){
		this(message,key.getBytes(),hashType);
	}
	
	public HMAC(String message,byte[] key,HashType hashType){
		this.message=message;
		this.hashType=hashType;
		this.key=key;
		buildPads();
	}
	/**
	 * Método estático para facilitar a criação rápida de HMACs
	 * @param message {@link String} Mensagem
	 * @param key {@link String} Chave
	 * @param hashType {@link HashType} Tipo de função Hash
	 * @return {@link String} Codificação HMAC da mensagem
	 */
	public static String encode(String message,String key, HashType hashType){
		HMAC hm=new HMAC(message, key, hashType);
		return hm.encode();
	}
	/**
	 * Método privado responsável pela construção dos arrays de padding.
	 * Este método foi criado pois esta rotina só deve ser executada uma vez se a chave não mudar. 
	 * Foi separado do método principal para aproveitar os arrays para outras computações se necessário.
	 * O setter da chave invoca o presente método e portanto não há necessidade de preocupar
	 * caso a chave mude no objecto. 
	 */
	private void buildPads(){
		int blockSize=blockSizeHash(hashType);
		IHash tmpHash=hashType.getHash();
		outerP=ArrayUtils.repeatByte((byte)0, blockSize);
		innerP=ArrayUtils.repeatByte((byte)0, blockSize);
		byte[] karr=key.clone();
		if(karr.length>blockSize){
			tmpHash.update(key);
			karr=tmpHash.digest();
		}
//		System.out.println("Key: "+ArrayUtils.ArrayCharDesc(key));
//		System.out.println("K0: "+ArrayUtils.ArrayCharDesc(key));
		for(int i=0;i<karr.length;i++){
				outerP[i]=karr[i];
				innerP[i]=karr[i];
		}
		for(int i=0;i<blockSize;i++){
			outerP[i]=(byte)((outerP[i]^outerPad)&Mask.MASK8);
			innerP[i]=(byte)((innerP[i]^innerPad)&Mask.MASK8);
		}
//		System.out.println("K0 xor Ipad: "+ArrayUtils.ArrayCharDesc(innerP));
//		System.out.println("K0 xor Opad: "+ArrayUtils.ArrayCharDesc(outerP));
//		System.out.println("______________________________________________________________");
	}
	/**
	 * Setter para a key.
	 * @param key {@link String}
	 */
	public void setKey(String key){
		this.key=key.getBytes();
		buildPads();
	}
	
	public void setKey(byte[] key){
		this.key=key;
		buildPads();
	}
	
	/**
	 * Setter para a mensagem
	 * @param key {@link String}
	 */
	public void setMessage(String message){
		this.message=message;
	}
	/**
	 * Setter para o tipo de função hash
	 * @param hashType {@link HashType}
	 */
	public void setHashType(HashType hashType){
		this.hashType=hashType;
	}
	/**
	 * Calcula o HMAC para uma menssagem e respectiva mensagem de codificação
	 * @return {@link String} Codificação HMAC da mensagem
	 */
	public String encode(){
		IHash innerHash=hashType.getHash();
		IHash outerHash=hashType.getHash();
		
		innerHash.update(innerP);
		innerHash.update(message.getBytes());
		innerHash.finish();
		
		outerHash.update(outerP);
		outerHash.update(innerHash.digest());
		
		outerHash.finish();
		
		return outerHash.hexDigest();
	}
	/**
	 * Método que devolve o tamanho do bloco de codificação interno ao algoritmo de hash.
	 * @param typeHash {@link HashType} Tipo de mecanismo hash
	 * @return {@link int} Tamanho do bloco do mecanismo de codificação hash
	 */
	private int blockSizeHash(HashType typeHash){
		switch(typeHash){
		case MD5:
			return 64;
		case SHA1:
			return 64;
		case SHA256:
			return 64;
		case SHA512:
			return 80;
		default:
			return 64;	
		}
	}
	
}
