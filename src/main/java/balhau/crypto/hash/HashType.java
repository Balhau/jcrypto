package balhau.crypto.hash;

/**
 * Enumerado que representa o tipo de função Hash 
 * @author balhau
 *
 */
public enum HashType {
	MD5,
	SHA1,
	SHA256,
	SHA512;
	/**
	 * Método que devolve uma instância do mecanismo de hash pretendido
	 * @return {@link IHash} Interface para funções Hash. Significa que poderá ser qualquer instância 
	 * de objecto representando funções de hash.
	 */
	public IHash getHash(){
		switch(this){
		case MD5:
			return new MD5();
		case SHA1:
			return new SHA1();
		case SHA256:
			return new SHA256();
		case SHA512:
			return new SHA512();
		default:
			return null;
		}
	}
}
