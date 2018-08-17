#include "stdafx.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <DbgHelp.h>
#include <fstream>
#include "BlackBone/Process/Process.h"

std::optional<IMAGE_SECTION_HEADER> getTextSectionHeader(blackbone::pe::PEImage &image) {
	for (auto section : image.sections()) {
		auto name = reinterpret_cast<const char *>(section.Name);
		if (strcmp(name, ".text") == 0) {
			return section;
		}
	}
	return {};
}

std::unique_ptr<uint8_t> getTextSectionBytes(std::wstring path) {
	blackbone::pe::PEImage image;
	image.Load(path);
	auto header = getTextSectionHeader(image);
	if (!header.has_value()) {
		return {};
	}
	auto sectionBytesPtr = image.ResolveRVAToVA(header->VirtualAddress);
	// Copy this onto the heap so that we can use it later
	std::unique_ptr<uint8_t> sectionBytes(new uint8_t[header->SizeOfRawData]);
	memcpy(sectionBytes.get(), (void *)sectionBytesPtr, header->SizeOfRawData);
	return sectionBytes;
}

struct ModifiedFunction {
	uint64_t startAddress;
};

int patchAllTheThings(blackbone::Process &process) {
	// Copy the module image so that we can parse it
	auto module = process.modules().GetModule(L"ntdll.dll");
	if (module == nullptr) {
		return 1;
	}
	std::unique_ptr<uint8_t> imageMem(new uint8_t[module->size]);
	process.memory().Read(module->baseAddress, module->size, imageMem.get());

	// Parse the image so that we can figure out where the text section is
	blackbone::pe::PEImage image;
	image.Load(imageMem.get(), module->size);
	auto textSectionHdr = getTextSectionHeader(image);
	if (!textSectionHdr.has_value()) {
		return 1;
	}

	// Copy the text section into our process
	std::unique_ptr<uint8_t> textSectionMem(new uint8_t[textSectionHdr->SizeOfRawData]);
	auto textSectionAddr = module->baseAddress + textSectionHdr->VirtualAddress;
	auto textSectionSize = textSectionHdr->SizeOfRawData;
	process.memory().Read(textSectionAddr, textSectionSize, textSectionMem.get());

	auto textSectionRVA = textSectionHdr->VirtualAddress;
	auto textSectionBytes = std::move(textSectionMem);
	auto imageVA = (uint64_t)module->baseAddress;
	auto imageSize = module->size;
	auto imagePath = module->fullPath;

	// Get the text section from the DLL file on disk
	auto originalTextSectionBytes = getTextSectionBytes(imagePath);

	// Build up a list of modified function RVAs so that we can figure out which functions they are associated with
	std::vector<uint64_t> modifiedFunctionRVAs;

	for (size_t i = 0; i < textSectionSize; i++) {
		if (originalTextSectionBytes.get()[i] != textSectionBytes.get()[i]) {
			auto RVA = textSectionRVA + i;
			modifiedFunctionRVAs.push_back(RVA);
		}
	}

	// Setup some things so that we can lookup symbols in our own process
	auto processHandle = process.core().handle();
	if (!SymInitialize(processHandle, NULL, true)) {
		std::cout << "Error: Failed to initialize symbol handler" << std::endl;
		return 1;
	}

	// Group the modified function RVAs by what function they belong to, using symbol info
	std::unordered_map<std::string, ModifiedFunction> modifiedFunctions;
	for (auto RVA : modifiedFunctionRVAs) {
		DWORD64 displacement = 0;

		char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;

		auto VA = imageVA + RVA;
		if (!SymFromAddr(processHandle, VA, &displacement, pSymbol)) {
			printf("Failed to lookup symbol at 0x%llx\n", VA);
			return 1;
		}
		modifiedFunctions[pSymbol->Name].startAddress = pSymbol->Address;
	}

	if (modifiedFunctions.empty()) {
		std::cout << "No modified functions detected" << std::endl;
		return 0;
	}

	std::cout << "Detected modified functions:" << std::endl;
	for (auto it : modifiedFunctions) {
		printf("0x%llx (%s)\n", it.second.startAddress, it.first.c_str());
	}
	std::cout << "Press Enter to patch functions";
	std::cin.ignore();

	// Write the original text section to the target process
	std::cout << std::endl << "Restoring original functions..." << std::endl;
	NTSTATUS status = process.memory().Write(imageVA + textSectionRVA, textSectionSize, originalTextSectionBytes.get());
	if (!NT_SUCCESS(status)) {
		std::cout << "Failed to patch functions" << std::endl;
		return 1;
	}
	std::cout << "Success" << std::endl;
	return 0;
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc != 2) {
		TCHAR szFileName[MAX_PATH + 1];
		GetModuleFileName(NULL, szFileName, MAX_PATH + 1);
		std::cout << "Usage: " << szFileName << " <process name>" << std::endl;
	}

	wchar_t *processName = argv[1];
	blackbone::Process process;
	NTSTATUS status = process.Attach(processName);
	int terminationStatus = 0;
	if (NT_SUCCESS(status)) {
		process.Suspend();
		terminationStatus = patchAllTheThings(process);
	}
	else {
		std::wcout << L"Failed to attach to " << processName << std::endl;
	}

	process.Detach();
	std::cout << "Press Enter to exit the program";
	std::cin.ignore();
	return terminationStatus;
}
