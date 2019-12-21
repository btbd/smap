#pragma once

#include <stdio.h>
#include <windows.h>

#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_internal.h>

#include <MinHook.h>
#pragma comment(lib, "minhook.lib")

#include <d3d11.h>
#pragma comment(lib, "d3d11.lib")

ImGuiWindow &BeginScene();
VOID EndScene(ImGuiWindow &window);