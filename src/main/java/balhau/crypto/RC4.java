package balhau.crypto;

import balhau.utils.ArrayUtils;

/**
 * Implementação do algoritmo RC4 de criptografia
 * @author balhau
 *
 */
public class RC4 {
	private int[] _matriz;
	private static int msize=256;
	private int[] _key;
	private int[]_expkey;
	
	public RC4(){
		this.initVectores();
	}
	
	/**
	 * Construção dos vectores
	 */
	private void initVectores(){
		int j=0;
		if(this._key==null)
			genKey();
		this._matriz=new int[msize];
		this._expkey=new int[msize];
		//inicialização dos vectores
		for(int i=0;i<msize;i++){
			this._matriz[i]=i;
			this._expkey[i]=this._key[i%this._key.length];
		}
		//permutação inicial do vector
		for(int i=0;i<msize;i++){
			j=(j+this._expkey[i]+this._matriz[i])%256;
			ArrayUtils.troca(_matriz, i, j);
		}
	}
	
	/**
	 * Geração da chave
	 */
	public void genKey(){
		int cmp=(int)Math.round(Math.random()*msize);
		this._key=new int[cmp];
		for(int i=0;i<cmp;i++)
			this._key[i]=(int)Math.round(Math.random()*msize);
	}
	
	/**
	 * Codifica dados a partir do algoritmo RC4 
	 * @param ptext {@link int[]} com o texto a codificar
	 * @return {@link int[]} com o texto codificado
	 */
	public CriptoData encode(int[] ptext){
		int[] out=new int[ptext.length];
		int i=0;
		int j=0;
		for(int k=0;k<ptext.length;k++){
			i=(i+1)%256;
			j=(j+_matriz[i])%256;
			out[k]=_matriz[(_matriz[i]+_matriz[j])%256]^ptext[k];
		}
		return new CriptoData(out, _key);
	}
	/**
	 * Método que descodifica dados encriptados a partir do algoritmo RC4
	 * @param cdata Objecto {@link CriptoData} com os dados e a chave resultantes da encriptação a partir
	 * do algoritmo RC4 
	 * @return Array {@link int[]} com a mensagem descodificada 
	 */
	public int[] decode(CriptoData cdata){
		int[] out=new int[cdata.Data.length];
		this._key=cdata.Key;
		initVectores();
		int i=0;
		int j=0;
		for(int k=0;k<cdata.Data.length;k++){
			i=(i+1)%256;
			j=(j+_matriz[i])%256;
			out[k]=_matriz[(_matriz[i]+_matriz[j])%256]^cdata.Data[k];
		}
		return out;
	}
	
	/**
	 * Geração da chave com especificação do tamanho em bytes.
	 * @param size Número de {@link byte}'s presentes na chave de encriptação
	 */
	public void genSizedKey(int size){
		int cmp=size;
		this._key=new int[cmp];
		for(int i=0;i<cmp;i++)
			this._key[i]=(int)Math.round(Math.random()*msize);
	}
}
