#include "stdafx.h"

ID3D11Device *device = nullptr;
ID3D11DeviceContext *immediateContext = nullptr;
ID3D11RenderTargetView *renderTargetView = nullptr;

HRESULT(*PresentOriginal)(IDXGISwapChain *swapChain, UINT syncInterval, UINT flags) = nullptr;
HRESULT(*ResizeOriginal)(IDXGISwapChain *swapChain, UINT bufferCount, UINT width, UINT height, DXGI_FORMAT newFormat, UINT swapChainFlags) = nullptr;

__declspec(dllexport) HRESULT PresentHook(IDXGISwapChain *swapChain, UINT syncInterval, UINT flags) {
	if (!device) {
		swapChain->GetDevice(__uuidof(device), reinterpret_cast<PVOID *>(&device));
		device->GetImmediateContext(&immediateContext);

		ID3D11Texture2D *renderTarget = nullptr;
		swapChain->GetBuffer(0, __uuidof(renderTarget), reinterpret_cast<PVOID *>(&renderTarget));
		device->CreateRenderTargetView(renderTarget, nullptr, &renderTargetView);
		renderTarget->Release();

		DXGI_SWAP_CHAIN_DESC desc;
		swapChain->GetDesc(&desc);

		ImGui_ImplDX11_Init(desc.OutputWindow, device, immediateContext);
		ImGui_ImplDX11_CreateDeviceObjects();
	}

	immediateContext->OMSetRenderTargets(1, &renderTargetView, nullptr);

	auto &window = BeginScene();
	window.DrawList->AddRectFilled(ImVec2(100, 100), ImVec2(200, 125), ImGui::GetColorU32({ 0, 0, 1, 1 }));
	window.DrawList->AddText(ImVec2(100, 100), ImGui::GetColorU32({ 1, 0, 0, 1 }), "Hello, world!");
	EndScene(window);

	return PresentOriginal(swapChain, syncInterval, flags);
}

__declspec(dllexport) HRESULT ResizeHook(IDXGISwapChain *swapChain, UINT bufferCount, UINT width, UINT height, DXGI_FORMAT newFormat, UINT swapChainFlags) {
	ImGui_ImplDX11_Shutdown();
	renderTargetView->Release();
	immediateContext->Release();
	device->Release();
	device = nullptr;

	return ResizeOriginal(swapChain, bufferCount, width, height, newFormat, swapChainFlags);
}

ImGuiWindow &BeginScene() {
	ImGui_ImplDX11_NewFrame();
	ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
	ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0, 0, 0, 0));
	ImGui::Begin("##scene", nullptr, ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoTitleBar);

	auto &io = ImGui::GetIO();
	ImGui::SetWindowPos(ImVec2(0, 0), ImGuiCond_Always);
	ImGui::SetWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y), ImGuiCond_Always);

	return *ImGui::GetCurrentWindow();
}

VOID EndScene(ImGuiWindow &window) {
	window.DrawList->PushClipRectFullScreen();
	ImGui::End();
	ImGui::PopStyleColor();
	ImGui::PopStyleVar(2);
	ImGui::Render();
}

VOID Main() {
	IDXGISwapChain      *swapChain    = nullptr;
	ID3D11Device        *device       = nullptr;
	ID3D11DeviceContext *context      = nullptr;
	auto                 featureLevel = D3D_FEATURE_LEVEL_11_0;

	DXGI_SWAP_CHAIN_DESC sd           = { 0 };
	sd.BufferCount                    = 1;
	sd.BufferDesc.Format              = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferUsage                    = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.Flags                          = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.OutputWindow                   = GetForegroundWindow();
	sd.SampleDesc.Count               = 1;
	sd.Windowed                       = TRUE;

	if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, 0, 0, &featureLevel, 1, D3D11_SDK_VERSION, &sd, &swapChain, &device, nullptr, &context))) {
		MessageBox(0, L"Failed to create D3D11 device and swap chain", L"Failure", MB_ICONERROR);
		return;
	}

	auto table = *reinterpret_cast<PVOID **>(swapChain);
	auto present = table[8];
	auto resize = table[13];

	context->Release();
	device->Release();
	swapChain->Release();

	MH_Initialize();

	MH_CreateHook(present, PresentHook, reinterpret_cast<PVOID *>(&PresentOriginal));
	MH_EnableHook(present);

	MH_CreateHook(resize, ResizeHook, reinterpret_cast<PVOID *>(&ResizeOriginal));
	MH_EnableHook(resize);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
	if (reason == DLL_PROCESS_ATTACH) {
		Main();
	}

	return TRUE;
}