package did

const (
	ArbitrumChainName     string = "arbitrum"
	EthereumChainName     string = "ethereum"
	GoerliChainName       string = "goerli"
	OkChainName           string = "okexchain"
	PolygonChainName      string = "polygon"
	PolygonZkEVMChainName string = "polygonzkevm"
	SepoliaChainName      string = "sepolia"
	SolanaChainName       string = "solana"
	HarmonyChainName      string = "harmony"
)

var ChainName2ContractConfigMap = map[string]ContractConfig{
	GoerliChainName:  {RpcUrl: "https://ethereum-goerli.publicnode.com", ContractAddr: "0x28e038d24Ebcf16BC386141224535650A667146e", ChainName: "goerli"},
	HarmonyChainName: {RpcUrl: "https://api.harmony.one", ContractAddr: "0x275D3fC4C492a8d743Fe9AAB42266fEf92c89995", ChainName: "harmony"},
	SolanaChainName:  {RpcUrl: "https://245022926.rpc.thirdweb.com", ContractAddr: "0x58C2AE9AE47a07A3D9928898BA32C00E4FE599Cc", ChainName: "solana"},
}

var ChainId2NameMap = map[int]string{
	1:          EthereumChainName,
	5:          GoerliChainName,
	66:         OkChainName,
	137:        PolygonChainName,
	1101:       PolygonZkEVMChainName,
	42161:      ArbitrumChainName,
	11155111:   SepoliaChainName,
	1666600000: HarmonyChainName,
	245022926:  SolanaChainName,
}

var ChainName2IdMap = map[string]int{
	EthereumChainName:     1,
	GoerliChainName:       5,
	OkChainName:           66,
	PolygonChainName:      137,
	PolygonZkEVMChainName: 1101,
	ArbitrumChainName:     42161,
	SepoliaChainName:      11155111,
	HarmonyChainName:      1666600000,
	SolanaChainName:       245022926,
}
