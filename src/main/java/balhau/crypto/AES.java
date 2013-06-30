package balhau.crypto;

import balhau.matematica.GGalois;
import balhau.matematica.MathUtils;
import balhau.utils.Sys;
import balhau.utils.ArrayUtils;

/**
 *  Classe de encriptação que utiliza o algoritmo de Rijndael para codificação e descodificação da informação.
 *  Este algoritmo é actualmente o AES (ADVANCED ENCRYPTION STANDARD) e a sua especificação foi publicada
 *  em Novembro, 26, 2001.
 *  Ver tambem o algoritmo {@link Camellia}
 * @author balhau
 *
 */
public class AES {
	
	
	public static byte CVALUE=(byte)99;
	public static int GF28=256;
	public static int GF2=2;
	private int[] _smatrix;
	private int[] _invsmatrix;
	private int[] _rcon;
	private int[] _key;
	private int[] _expkey;
	private int _blocksize;
	private int _numrounds;
	private int _keysize;
	private int _wordsize;
	private AESType _tipo;
 	
	/**
	 * Construtor da classe.
	 * Responsável pela geração das S-Matrix e do array que contem as Round Constants. Matrizes necessárias
	 * para acelerar o cômputo das permutações durante a execução do algoritmo
	 * @param tipo {@link AESType} representando o tipo de codificação do AES
	 */
	public AES(AESType tipo){
		_smatrix=FastCreateSMatrix();
		_invsmatrix=FastCreateInvSMatrix();
		_rcon=createRConArray();
		_tipo=tipo;
		setupFromType(tipo);
	}
	/**
	 * Construtor sem especificação do tipo de codificação, aceita por defeito a codificação a 256 bits
	 */
	public AES(){
		_smatrix=FastCreateSMatrix();
		_invsmatrix=FastCreateInvSMatrix();
		_rcon=createRConArray();
		_tipo=AESType.AES256;
		setupFromType(_tipo);
	}
	
	public void setKey(int[] chave){
		System.out.println(_keysize);
		if(chave.length!=(_keysize*4))
			return;
		this._key=chave;
		this._expkey=this.KeyExpansion(_key);
	}
	
	public int[] getKey(){
		return this._key;
	}
	
	private void setupFromType(AESType tipo){
		_blocksize=4;
		_wordsize=4;
		switch (tipo) {
		case AES128:
			_keysize=4;
			_numrounds=10;
			break;
		case AES192:
			_keysize=6;
			_numrounds=12;
			break;
		case AES256:
			_keysize=8;
			_numrounds=14;
			break;
		default:
			break;
		}
	}
	
	/**
	 * Método que gera um bloco de informação aleatório, útil para efectuar testes aos mecanismos
	 * de encriptação
	 * @return {@link int[]} Array de inteiros correspondendo ao bloco de bytes que compõe o 
	 * algoritmo de encriptação.
	 */
	public static int[] genRandBlockState(){
		int[] out=new int[16];
		for(int i=0;i<16;i++){
			out[i]=(int)Math.round(Math.random()*255);
		}
		return out;
	}
	
	/**
	 * Método que efectua a substituição dos bytes através da S-Matrix
	 * @param bts {@link int[]} array de bytes que se pretendem substituir a partir da S-Matrix
	 * @return {@link int[]} array de bytes que se pretendem substituir a partir da S-Matrix
 	 */
	private int[] SubBytes(int[] bts)
	{ 
		int out[]=new int[bts.length];
		for(int i=0;i<bts.length;i++){
			out[i]=_smatrix[bts[i]];
		}
		return out;
	}
	/**
	 * Método que inverso ao {@link SubBytes}
	 * @param bts {@link int[]} array de bytes
	 * @return {@link int[]} array substituido
	 */
	private int[] InvSubBytes(int[] bts){
		int out[]=new int[bts.length];
		for(int i=0;i<bts.length;i++){
			out[i]=_invsmatrix[bts[i]];
		}
		return out;
	}
	
	public void setType(AESType tipo){
		this._tipo=tipo;
		setupFromType(tipo);
	}
	
	/**
	 * Gera uma chave em função do tipo de encriptação 
	 * @return {@link int[]} array de inteiros
	 */
	public void geraKey(){
		this._key=new int[this._keysize*this._wordsize];
		for(int i=0;i<this._keysize*this._wordsize;i++){
			this._key[i]=(int)Math.round(Math.random()*255);
		}
		this._expkey=KeyExpansion(this._key);
	}
	
	/**
	 * Método que efectua a permuta de linhas da  matrix 4x4 de bytes
	 * que entra sob a forma de array [a_1,a_2,a_3,a_4,b_1,...,b_4,c_1...,c_4,d_1,...,d_4]
	 * @param bts Array, estado,  {@link byte[]} de dimensão 4x4
	 */
	public int[] shiftRows(int[] bts){
		if(bts.length!=16)
			return null;
		int[] out=bts.clone();
		int[] aux;
		for(int i=0;i<4;i++){
			aux=ArrayUtils.SubArrayInt(out, i*4, i*4+3);
			for(int j=0;j<i;j++){
				rodaWord(aux);
			}
			out[i*4]=aux[0];
			out[i*4+1]=aux[1];
			out[i*4+2]=aux[2];
			out[i*4+3]=aux[3];
		}
		return out;
	}
	
	/**
	 * Método que inverte a rotação das linhas, utilizado no algoritmmo de desencriptação do AES
	 * @param bts Bloco de estado 16 bytes
	 * @return bloco de estado 16bytes
	 */
	public int[] InvShiftRows(int[] bts){
		if(bts.length!=16)
			return null;
		int[] out=bts.clone();
		int[] aux;
		for(int i=0;i<4;i++){
			aux=ArrayUtils.SubArrayInt(out, i*4, i*4+3);
			for(int j=0;j<i;j++){
				InvRodaWord(aux);
			}
			out[i*4]=aux[0];
			out[i*4+1]=aux[1];
			out[i*4+2]=aux[2];
			out[i*4+3]=aux[3];
		}
		return out;
	}
	
	/**
	 * Devolve uma string com a descrição do state block 
	 * @param bts {@link byte[]} valor do state block
	 * @return {@link String} descrição do state block
	 */
	public static String BlockStateToString(byte[] bts){
		String st="";
		for(int i=0;i<16;i++){
			if(i%4==0)
				st+=Sys.EOL;
			else
				st+=",";
			st+=MathUtils.hexValue(bts[i]);
		}
		return st;
	}
	
	public byte xtime(byte bt){
		return (byte)(((bt)<<1)^27);
	}
	/**
	 * A S-Matrix do algoritmo AES pode ser construida à custa da aritmética de GF(2). Este método utiliza a função
	 * {@link createEntrySMatrix} para criar a entradas na matriz.
	 * @return
	 */
	public static byte[] createSMatrix(){
		byte[] bts=new byte[256];
		for(int i=0;i<255;i++){
			bts[i]=createEntrySMatrix((byte)i);
		}
		return bts;
	}
	
	public static int[] createRConArray(){
		int[] rcon={0x1,0x00,0x00,0x00,0x2,0x00,0x00,0x00,0x4,0x00,0x00,0x00,0x8,0x00,0x00,0x00,0x10,0x00,
				0x00,0x00,0x20,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x80,0x00,0x00,0x00,
				0x1b,0x00,0x00,0x00,0x36,0x00,0x00,0x00};
		return rcon;
	}
	/**
	 * Método que imprime a S-Matrix
	 */
	public static void PrintSMAtriz(int[] sm){
		System.out.println("______________________________________________________________________________");
		System.out.println("________________________________S-MATRIZ______________________________________");
		for(int i=-16;i<256;i++){
			if(i>=0){
				if(i%16==0){
					System.out.println("");
					System.out.print(MathUtils.hexValue(i/16)+"--");
				}
				else
					System.out.print(",");
				System.out.print(MathUtils.hexValue(sm[i]));
			}
			else
			{
				if(i==-16)
					System.out.print("---");
				System.out.print(MathUtils.hexValue(i+16)+"  ");
			}
		}
		System.out.println();
		System.out.println("______________________________________________________________________________");
	}
	/**
	 * Método que mistura uma coluna. Método auxiliar para a implementação do {@link MixColumns}
	 * @param Array de {@link int[]} representando os 4 bytes da coluna do bloco de estado
	 * @return Array de {@link int[]} representando os 4 bytes do misturados
	 */
	public static int[] MixColumn(int[] arr){
		if(arr.length!=4)
			return null;
		int[] out=new int[4];
		out[0]=MultGalois(0x02, arr[0])^MultGalois(0x3, arr[1])^arr[2]^arr[3];
		out[1]=arr[0]^MultGalois(0x2, arr[1])^MultGalois(0x3, arr[2])^arr[3];
		out[2]=arr[0]^arr[1]^MultGalois(0x2, arr[2])^MultGalois(0x3,arr[3]);
		out[3]=MultGalois(0x3, arr[0])^arr[1]^arr[2]^MultGalois(0x2, arr[3]);
		return out;
	}
	
	public void printKeyExpanded(){
		int[] kexp=this.KeyExpansion(_key);
		int k=0;
		for(int i=0;i<kexp.length;i+=4){
			System.out.println(k+": "+ArrayUtils.ArrayIntHEXDesc(ArrayUtils.SubArrayInt(kexp, i, i+3)));
			k++;
		}
	}
	/**
	 * Método responsável por efectuar a mistura de colunas no algoritmo AES
	 * @param arrCol {@link int[]} Array de inteiros com 16 valores correspondendo ao bloco estado
	 * @return bloco {@link int[]} array de inteiros com 16 valores correspondendo ao bloco de estado após mistura das colunas
	 */
	public static int[] MixColumns(int[] arrCol){
		if(arrCol.length!=16)
			return null;
		int[] out=new int[16];
		int[] axx=new int[4];
		int[] colaux;
		for(int i=0;i<4;i++){
			axx[0]=arrCol[i];
			axx[1]=arrCol[i+4];
			axx[2]=arrCol[i+8];
			axx[3]=arrCol[i+12];
			
			colaux=MixColumn(axx);
			out[i]=colaux[0];
			out[i+4]=colaux[1];
			out[i+8]=colaux[2];
			out[i+12]=colaux[3];
		}
		return out;
	}
	
	/**
	 * Método que efectua a mistura de colunas para o algoritmo de desencriptação
	 * @param arrCol {@link int[]} array com 16 inteiros correspondendo ao block state
	 * @return {@link int[]} array de inteiros correspondente ao block state misturado 
	 */
	public static int[] InvMixColumns(int[] arrCol){
		if(arrCol.length!=16)
			return null;
		int[] out=new int[arrCol.length];
		int[] axx=new int[4];
		int[] colaux;
		for(int i=0;i<4;i++){
			axx[0]=arrCol[i];
			axx[1]=arrCol[i+4];
			axx[2]=arrCol[i+8];
			axx[3]=arrCol[i+12];
			colaux=InvMixColumn(axx);
			out[i]=colaux[0];
			out[i+4]=colaux[1];
			out[i+8]=colaux[2];
			out[i+12]=colaux[3];
		}
		return out;
	}
	/**
	 * Método que efectua a mistura de uma coluna
	 * @param word {@link int[]} array de 4 inteiros representando uma palavra, ou coluna do block state
	 * @return {@link int[]} array de 4 inteiros representando a palavra misturada.
	 */
	private static int[] InvMixColumn(int[] word){
		int[] out=new int[word.length];
		out[0]=MultGalois(0x0e, word[0])^MultGalois(0x0b, word[1])^MultGalois(0x0d, word[2])^MultGalois(0x09, word[3]);
		out[1]=MultGalois(0x09, word[0])^MultGalois(0x0e, word[1])^MultGalois(0x0b, word[2])^MultGalois(0x0d, word[3]);
		out[2]=MultGalois(0x0d, word[0])^MultGalois(0x09, word[1])^MultGalois(0x0e, word[2])^MultGalois(0x0b, word[3]);
		out[3]=MultGalois(0x0b, word[0])^MultGalois(0x0d, word[1])^MultGalois(0x09, word[2])^MultGalois(0x0e, word[3]);
		return out;
	}
	
	/**
	 * Método que devolve o valor correspondente ao byte na SMatriz
	 * @param b {@link byte} byte que pretendemos corresponder na Matriz
	 * @return o {@link byte} correspondente da Matriz
	 */
	public static byte createEntrySMatrix(byte b){
		byte b1,b2,b3,b4,b5,b6,b7,b8;
		GGalois gf1=new GGalois(GF2);
		GGalois gf2=new GGalois(GF2);
		GGalois[] gfs;
		gf1.GF2FromInt(283);
		gf2.GF2FromInt(MathUtils.byteToIntValue(b));
		gfs=GGalois.EAEuclides(gf2, gf1);
		b=(byte)GGalois.GFMod(gfs[1],gf1).GF2ToInt();
		b1=(byte)(getNBit(b, 0)^getNBit(b,4)^getNBit(b,5)^getNBit(b,6)^getNBit(b,7));
		b2=(byte)(getNBit(b, 0)^getNBit(b,1)^getNBit(b,5)^getNBit(b,6)^getNBit(b,7));
		b3=(byte)(getNBit(b, 0)^getNBit(b,1)^getNBit(b,2)^getNBit(b,6)^getNBit(b,7));
		b4=(byte)(getNBit(b, 0)^getNBit(b,1)^getNBit(b,2)^getNBit(b,3)^getNBit(b,7));
		b5=(byte)(getNBit(b, 0)^getNBit(b,1)^getNBit(b,2)^getNBit(b,3)^getNBit(b,4));
		b6=(byte)(getNBit(b, 1)^getNBit(b,2)^getNBit(b,3)^getNBit(b,4)^getNBit(b,5));
		b7=(byte)(getNBit(b, 2)^getNBit(b,3)^getNBit(b,4)^getNBit(b,5)^getNBit(b,6));
		b8=(byte)(getNBit(b, 3)^getNBit(b,4)^getNBit(b,5)^getNBit(b,6)^getNBit(b,7));
		return (byte)(((b8<<7)|(b7<<6)|(b6<<5)|(b5<<4)|(b4<<3)|(b3<<2)|(b2<<1)|b1)^AES.CVALUE);
	}
	/**
	 * Devolve o byte com a coordenada i igual ao bt[i] e as restantes coordenadas todas a nulo por exemplo getNBit(111,1)-> 1
	 * getNBit(111,2)-->1;
	 * @param bt Byte
	 * @param i Coordenada
	 * @return Byte
	 */
	public static byte getNBit(byte bt,int i){
		return (byte)((bt>>i)&1);
	}
	/**
	 * Método que encripta blocos de 16 bytes de dados
	 * @param bt {@link int[]} representando o plaintext  
	 */
	public int[] encodeBlock(int[] bt){
		if(bt.length!=16)
			return null;
		int[] out=new int[16];
		int[] subex=ArrayUtils.SubArrayInt(_expkey, 0, 15);
		out=AddRoundKey(transposeBlock(bt), transposeBlock(subex));
		for(int i=1;i<_numrounds;i++){
			subex=ArrayUtils.SubArrayInt(_expkey, i*16, i*16+15);
//			System.out.println("SUBKEY: "+ArrayUtils.ArrayIntHEXDesc(subex));
//			System.out.println("OUT_INIT: "+ArrayUtils.ArrayIntHEXDesc(out));
			out=this.SubBytes(out);
//			System.out.println("OUT_SUB: "+ArrayUtils.ArrayIntHEXDesc(out));
			out=shiftRows(out);
//			System.out.println("OUT_SHIFT: "+ArrayUtils.ArrayIntHEXDesc(out));
//			System.out.println("OUTLENG: "+out.length);
			out=MixColumns(out);
//			System.out.println("OUT_MIX: "+ArrayUtils.ArrayIntHEXDesc(out));
			out=AddRoundKey(out, transposeBlock(subex));
			//System.out.println("OUT: "+ArrayUtils.ArrayIntHEXDesc(out));
		}
		subex=ArrayUtils.SubArrayInt(_expkey, _numrounds*16, _numrounds*16+15);
		out=this.SubBytes(out);
		out=this.shiftRows(out);
		out=this.AddRoundKey(out, transposeBlock(subex));
//		System.out.println("OUT: "+ArrayUtils.ArrayIntHEXDesc(out));
		return out;
	}
	
	/**
	 * Método que efectua a descodificação de um bloco de 16bytes codificado.
	 * @param bt {@link int[]} Array de 16 inteiros com os valores dos bytes
	 * @return {@link int[]} array de 16 inteiros com os valores dos bytes
	 */
	public int[] decodeBlock(int[] bt){
		if(bt.length!=16)
			return null;
		int[] out;
		int[] subex=ArrayUtils.SubArrayInt(_expkey, _numrounds*16,  _numrounds*16+15);
		out=AddRoundKey(bt, transposeBlock(subex));
//		System.out.println("KeyR: "+ArrayUtils.ArrayIntHEXDesc(transposeBlock(subex)));
//		System.out.println("KR: "+ArrayUtils.ArrayIntHEXDesc(out));
		//out=InvShiftRows(out);
//		System.out.println("IShiftROw: "+ArrayUtils.ArrayIntHEXDesc(out));
		for(int i=_numrounds-1;i>=1;i--){
			subex=ArrayUtils.SubArrayInt(_expkey, i*16, i*16+15);
			out=InvShiftRows(out);
//			System.out.println("InvShiftR: "+ArrayUtils.ArrayIntHEXDesc(out));
			out=InvSubBytes(out);
//			System.out.println("InvSubBytesR: "+ArrayUtils.ArrayIntHEXDesc(out));
			out=AddRoundKey(out, transposeBlock(subex));
//			System.out.println("InvAddRoundR: "+ArrayUtils.ArrayIntHEXDesc(out));
			out=InvMixColumns(out);
//			System.out.println("InvMixColR: "+ArrayUtils.ArrayIntHEXDesc(out));
		}
		subex=ArrayUtils.SubArrayInt(_expkey, 0, 15);
		out=InvShiftRows(out);
//		System.out.println("InvShiftR: "+ArrayUtils.ArrayIntHEXDesc(out));
		out=InvSubBytes(out);
//		System.out.println("InvSubBytesR: "+ArrayUtils.ArrayIntHEXDesc(out));
		out=AddRoundKey(out, transposeBlock(subex));
		out=transposeBlock(out);
		return out;
	}
	/**
	 * Método que efectua a transposição de um bloco de estado
	 * @param block {@link int[]} bloco de estado
	 * @return bloco {@link int[]} de estado
	 */
	private int[] transposeBlock(int[] block){
		if(block.length!=16)
			return null;
		int[] out=new int[16];
		for(int i=0;i<4;i++){
			out[i]=block[i*4];
			out[i+4]=block[i*4+1];
			out[i+8]=block[i*4+2];
			out[i+12]=block[i*4+3];
		}
		return out;
	}
	/**
	 * Devolve a multiplicação de a por b mod v(x), onde v(x)=x^8+x^4+x^3+x+1
	 * @param a {@link int} positivo 
	 * @param b {@link int} positivo
	 * @return ab mod v(x)
	 */
	public static int MultGalois(int a,int b){
		int res=0;
		while(a!=0){
			if((a&1)==1)
				res^=b;
			b=b<<1;
			if((b & 0x100)>0)
				b=b^0x11b;
			a=a>>1;
		}
		return res;
	}
	
	/**
	 * Cálculo do inverso no corpo de Galois com força bruta
	 * @param a {@link int} representando o polinómio a para o qual se pretende determinar o inverso.
	 * @return a^-1 {@link int} inverso do polinómio a
	 */
	public static int InversoGaloisBrute(int a){
		int c;
		for(c=0;c<256;c++){
			if(MultGalois(a, c)==1)
				return c;
		}
		return 0;
	}
	
	/**
	 * Método optimizado para encontrar o inverso no corpo de Galois
	 * @param a {@link int} representando o polinómio a para o qual se pretende determinar o inverso.
	 * @return a^-1 {@link int} inverso do polinómio a
	 */
	public static int InversoGalois(int a){
		int b,c;
		b=1;
		for(c=0;c<7;c++){
			b=MultGalois(MultGalois(b, b), a);
		}
		return MultGalois(b, b);
	}
	
	/**
	 * Método optimizado para criação da S-Matrix 
	 * @return {@link int[]} com os coeficientes da S-Matrix
	 */
	public static int[] FastCreateSMatrix(){
		int[] out=new int[256];
		byte b;
		int b1,b2,b3,b4,b5,b6,b7,b8;
		for(int i=0;i<256;i++){
			b=(byte)(InversoGalois(i));
			b1=(getNBit(b, 0)^getNBit(b,4)^getNBit(b,5)^getNBit(b,6)^getNBit(b,7));
			b2=(getNBit(b, 0)^getNBit(b,1)^getNBit(b,5)^getNBit(b,6)^getNBit(b,7));
			b3=(getNBit(b, 0)^getNBit(b,1)^getNBit(b,2)^getNBit(b,6)^getNBit(b,7));
			b4=(getNBit(b, 0)^getNBit(b,1)^getNBit(b,2)^getNBit(b,3)^getNBit(b,7));
			b5=(getNBit(b, 0)^getNBit(b,1)^getNBit(b,2)^getNBit(b,3)^getNBit(b,4));
			b6=(getNBit(b, 1)^getNBit(b,2)^getNBit(b,3)^getNBit(b,4)^getNBit(b,5));
			b7=(getNBit(b, 2)^getNBit(b,3)^getNBit(b,4)^getNBit(b,5)^getNBit(b,6));
			b8=(getNBit(b, 3)^getNBit(b,4)^getNBit(b,5)^getNBit(b,6)^getNBit(b,7));
			out[i]=((b8<<7)|(b7<<6)|(b6<<5)|(b5<<4)|(b4<<3)|(b3<<2)|(b2<<1)|b1)^AES.CVALUE;
		}
		return out;
	}
	/**
	 * Método rápido de criação da S-Matriz inversa
	 * @return int[] S-Matriz inversa 
	 */
	public static int[] FastCreateInvSMatrix(){
		int[] out=new int[256];
		int[] sm=FastCreateSMatrix();
		for(int i=0;i<256;i++){
			out[sm[i]]=i;
		}
		return out;
	}
	/**
	 * Efectua o XOR entre o state block e a state key
	 * @param blockB {@link byte[]} State intblock
	 * @param blockKey {@link byte[]} State key
	 * @return {@link byte[]}
	 */
	public int[] AddRoundKey(int[] blockB,int[] blockKey){
		int[] out=new int[blockB.length];
		if(blockKey.length!=blockB.length)
			return null;
		for(int i=0;i<blockB.length;i++){
			out[i]=blockB[i]^blockKey[i];
		}
		return out;
	}
	
	/***
	 * Método que efectua a expansão da chave
	 * @param key {@link int[]} chave de encriptação utilizada no AES
	 * @return {@link int[]} chave expandida
	 */
	public int[] KeyExpansion(int[] key){
		int wordsize=4;
		int maxlen=_blocksize*(_numrounds+1)*wordsize;
		int[] expkey=new int[maxlen];
		int[] prev;
		int[] prev2;
		int crounds=0;
//		System.out.println("_______________________________________");
//		System.out.println("MAXLEN: "+maxlen);
//		System.out.println("KESZ: "+_keysize*wordsize);
		//Copia as palavras da chave (blocos de quatro int)
		for(int i=0;i<_keysize*wordsize;i++){
			expkey[i]=key[i];
		}
		//Expande a chave comprimento da chave x tamanho do bloco x numero de rounds x tamanho da palavra 
		//i+=4, número de byts numa palavra
//		System.out.println("ExpK: "+ArrayUtils.ArrayIntHEXDesc(expkey));
		for(int i=_keysize*wordsize;i<maxlen;i+=wordsize){
			//Palavra anterior
			prev=ArrayUtils.SubArrayInt(expkey, i-4, i-1);
//			System.out.println("ANT: "+ArrayUtils.ArrayIntHEXDesc(prev));
			prev2=ArrayUtils.SubArrayInt(expkey, i-(_keysize*wordsize), i-(_keysize*wordsize)+wordsize-1);
//			System.out.println("ANT2: "+ArrayUtils.ArrayIntHEXDesc(prev2));
			if((i%(_keysize*wordsize))==0){
//				System.out.println("VALI: "+i);
//				System.out.println("PP: "+ArrayUtils.ArrayIntHEXDesc(ArrayUtils.SubArrayInt(expkey, i-4, i-1)));
//				System.out.println("PREV: "+ArrayUtils.ArrayIntHEXDesc(prev));
//				System.out.println("RPREV: "+ArrayUtils.ArrayIntHEXDesc(this.rodaWord(prev)));
				this.rodaWord(prev);
//				System.out.println("ROD: "+ArrayUtils.ArrayIntHEXDesc(prev));
//				System.out.println("SUB: "+ArrayUtils.ArrayIntHEXDesc(this.SubBytes(prev)));
//				System.out.println("RCON: "+ArrayUtils.ArrayIntHEXDesc(ArrayUtils.SubArrayInt(this._rcon,crounds*wordsize,crounds*wordsize+3)));
				prev=ArrayUtils.IntXORInt(this.SubBytes(prev),ArrayUtils.SubArrayInt(this._rcon,crounds*wordsize,crounds*wordsize+3));
//				System.out.println("XOR: "+ArrayUtils.ArrayIntHEXDesc(prev));
				crounds++;
			}
			else if(_keysize>6){
				if(i%4==0)
				{
					if(((int)(i/4))%_keysize==4){
						prev=this.SubBytes(prev);
//						System.out.println("SUB: "+ArrayUtils.ArrayIntHEXDesc(prev));
					}
				}
			}
			
			//Passa os bytes para o array final
			prev=ArrayUtils.IntXORInt(prev2, prev);
//			System.out.println("ACTUAL: "+ArrayUtils.ArrayIntHEXDesc(prev));
//			System.out.println("_______________________________________");
			expkey[i]=prev[0];
			expkey[i+1]=prev[1];
			expkey[i+2]=prev[2];
			expkey[i+3]=prev[3];
		}
		return expkey;
	}
	/**
	 * Método que roda a word (conjunto de 4 bytes). Necessário para expansão da chave
	 * @param word Inteiro com a informação presente em 4 bytes
	 * @return word Inteiro com o valor de 4 bytes
	 */
	private void rodaWord(int[] word){
		int aux=word[0];
		word[0]=word[1];
		word[1]=word[2];
		word[2]=word[3];
		word[3]=aux;
	}
	
	/**
	 * Método que efectua a rotação da palavra para o algoritmo de descodificação no algoritmo AES
	 * @param word {@link int[]} palavra a rodar
	 */
	private void InvRodaWord(int[] word){
		int aux=word[3];
		word[3]=word[2];
		word[2]=word[1];
		word[1]=word[0];
		word[0]=aux;
	}
	
	/**
	 * Método que decripta os dados
	 * @param bt {@link byte[]} representando o plaintext  
	 * @return {@link byte[]} representando a criptext
	 */
	public byte[] decode(byte[] bt)
	{
		return null;
	}
}