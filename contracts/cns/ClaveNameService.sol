// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {ERC721} from '@openzeppelin/contracts/token/ERC721/ERC721.sol';
import {ERC721Burnable} from '@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol';
import {AccessControl} from '@openzeppelin/contracts/access/AccessControl.sol';

/**
 * @title ClaveNameService
 * @author https://getclave.io
 * @notice https://github.com/stevegachau/optimismresolver
 * TODO: May limit for Clave accounts 
 */
contract ClaveNameService is ERC721, ERC721Burnable, AccessControl {
    struct NameAssets {
        uint256 id;
        uint256 renewals;
    }

    struct LinkedNames {
        string name;
    }

    uint256 private totalSupply_;
    bytes32 public constant REGISTERER_ROLE = keccak256('REGISTERER_ROLE');
    uint256 public expiration = 365 days;
    string public ensDomain;
    string public baseTokenURI;
    bool public allowRenewals;

    mapping(string => NameAssets) public namesToAssets;
    mapping(uint256 => LinkedNames) public idsToNames;

    event NameRegistered(string indexed name, address indexed owner);
    event NameDeleted(string indexed name, address indexed owner);
    event NameTransferred(string indexed name, address indexed from, address indexed to);
    event NameRenewed(string indexed name, address indexed owner);
    event NameExpired(string indexed name, address indexed owner);

    constructor(string memory domain, string memory baseURI) ERC721('ClaveNameService', 'CNS') {
        ensDomain = domain;
        baseTokenURI = baseURI;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function resolve(string memory _name) external view returns (address) {
        // Domain NFTs are stored against the hashes of domains
        string memory domain = toLower(_name);
        bytes32 domainHash = keccak256(abi.encodePacked(domain));
        return ownerOf(uint256(domainHash));
    }

    function totalSupply() external view returns (uint256) {
        return totalSupply_;
    }

    function register(
        address to,
        string memory _name
    ) external onlyRoleOrOwner(to) returns (uint256) {
        string memory domain = toLower(_name);
        require(bytes(domain).length != 0, '[register] Null name');
        require(isAlphanumeric(domain), '[register] Unsupported characters.');
        require(namesToAssets[domain].id == 0, '[register] Already registered.');

        uint256 newTokenId = uint256(keccak256(abi.encodePacked(domain)));
        namesToAssets[domain] = NameAssets(newTokenId, block.timestamp);
        idsToNames[newTokenId].name = domain;

        _mint(to, newTokenId);
        emit NameRegistered(domain, to);
        return newTokenId;
    }

    function renewName(string memory _name) external isRenewalsAllowed {
        NameAssets storage asset = namesToAssets[_name];

        require(asset.id != 0, '[renewName] Not registered.');
        require(ownerOf(asset.id) == msg.sender, '[renewName] Not owner.');

        asset.renewals = block.timestamp;

        emit NameRenewed(_name, msg.sender);
    }

    function expireName(address to, string memory _name) external isRenewalsAllowed {
        string memory domain = toLower(_name);
        NameAssets memory asset = namesToAssets[domain];

        require(asset.id != 0, '[expireName] Not registered.');
        require(asset.renewals + expiration < block.timestamp, '[expireName] Renewal not over.');

        delete idsToNames[asset.id];
        delete namesToAssets[domain];

        emit NameExpired(domain, to);

        _burn(asset.id);
    }

    function setEnsDomain(
        string memory domain
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (string memory) {
        ensDomain = domain;
        return ensDomain;
    }

    function setBaseTokenURI(
        string memory baseURI
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (string memory) {
        baseTokenURI = baseURI;
        return baseTokenURI;
    }

    function flipRenewals() external onlyRole(DEFAULT_ADMIN_ROLE) {
        allowRenewals = !allowRenewals;
    }

    function setExpirationTime(uint256 expirationTime) external onlyRole(DEFAULT_ADMIN_ROLE) {
        expiration = expirationTime;
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        string memory domain = idsToNames[tokenId].name;
        string memory tokenlink = string(abi.encodePacked(baseTokenURI, domain));

        return tokenlink;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721, AccessControl) returns (bool) {
        return
            ERC721.supportsInterface(interfaceId) || AccessControl.supportsInterface(interfaceId);
    }

    function burn(uint256 tokenId) public override(ERC721Burnable) {
        string memory domain = idsToNames[tokenId].name;

        delete idsToNames[tokenId];
        delete namesToAssets[domain];

        emit NameDeleted(domain, msg.sender);

        super.burn(tokenId);
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal override {
        require(balanceOf(to) == 0, '[] Already have name.');

        string memory domain = idsToNames[tokenId].name;
        emit NameTransferred(domain, from, to);
    }

    function toLower(string memory str) private pure returns (string memory) {
        bytes memory bStr = bytes(str);
        bytes memory bLower = new bytes(bStr.length);
        for (uint i = 0; i < bStr.length; i++) {
            // Uppercase character...
            if ((uint8(bStr[i]) >= 65) && (uint8(bStr[i]) <= 90)) {
                // So we add 32 to make it lowercase
                bLower[i] = bytes1(uint8(bStr[i]) + 32);
            } else {
                bLower[i] = bStr[i];
            }
        }
        return string(bLower);
    }

    function isAlphanumeric(string memory str) private pure returns (bool) {
        bytes memory b = bytes(str);
        for (uint i; i < b.length; i++) {
            bytes1 char = b[i];
            if (!(char > 0x2F && char < 0x3A) && !(char > 0x60 && char < 0x7B)) return false;
        }
        return true;
    }

    modifier onlyRoleOrOwner(address to) {
        require(
            to == msg.sender ||
                hasRole(REGISTERER_ROLE, msg.sender) ||
                hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            '[] Not authorized.'
        );

        _;
    }

    modifier isRenewalsAllowed() {
        require(allowRenewals, '[isRenewalsEnabled] Renewals disabled.');
        _;
    }
}
