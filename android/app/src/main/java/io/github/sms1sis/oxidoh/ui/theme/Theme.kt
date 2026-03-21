package io.github.sms1sis.oxidoh.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat

// ── Sci-fi color palette ──────────────────────────────────────────────────────
// Tactical HUD: deep void background, electric cyan primary, amber warning,
// crimson threat — inspired by submarine command systems and military HUDs.

val VoidBlack      = Color(0xFF000A0F)   // deepest background
val Abyss          = Color(0xFF010D14)   // surface
val DeepConsole    = Color(0xFF021420)   // elevated surface
val ConsolePanel   = Color(0xFF031D2C)   // cards
val GridLine       = Color(0xFF0A2A3D)   // dividers / grid

val CyanPrimary    = Color(0xFF00E5FF)   // electric cyan — primary actions
val CyanDim        = Color(0xFF0097A7)   // dimmed cyan
val CyanGhost      = Color(0xFF00E5FF).copy(alpha = 0.08f)
val NeonGreen      = Color(0xFF00FF9C)   // "systems nominal" green
val AmberAlert     = Color(0xFFFFB300)   // warning / medium latency
val CrimsonThreat  = Color(0xFFFF1744)   // error / high threat
val GridWhite      = Color(0xFFCFE8F0)   // primary text
val GhostText      = Color(0xFF4A7A8A)   // secondary / placeholder text

// ── Light Scheme (Daylight HUD) ──────────────────────────────────────────────
private val LightSciFiColorScheme = lightColorScheme(
    primary              = CyanDim,
    onPrimary            = Color.White,
    primaryContainer     = Color(0xFFE0F7FA),
    onPrimaryContainer   = CyanDim,
    secondary            = Color(0xFF00897B),
    onSecondary          = Color.White,
    background           = Color(0xFFF0F4F8),
    onBackground         = Color(0xFF102A43),
    surface              = Color.White,
    onSurface            = Color(0xFF102A43),
    surfaceVariant       = Color(0xFFD9E2EC),
    onSurfaceVariant     = Color(0xFF486581),
    outline              = Color(0xFFBCCCDC),
)

// ── Sci-fi color scheme ───────────────────────────────────────────────────────
private val SciFiColorScheme = darkColorScheme(
    primary              = CyanPrimary,
    onPrimary            = VoidBlack,
    primaryContainer     = Color(0xFF003344),
    onPrimaryContainer   = CyanPrimary,
    secondary            = NeonGreen,
    onSecondary          = VoidBlack,
    secondaryContainer   = Color(0xFF002918),
    onSecondaryContainer = NeonGreen,
    tertiary             = AmberAlert,
    onTertiary           = VoidBlack,
    tertiaryContainer    = Color(0xFF2C1F00),
    onTertiaryContainer  = AmberAlert,
    error                = CrimsonThreat,
    errorContainer       = Color(0xFF2D0010),
    onErrorContainer     = CrimsonThreat,
    background           = VoidBlack,
    onBackground         = GridWhite,
    surface              = Abyss,
    onSurface            = GridWhite,
    surfaceVariant       = ConsolePanel,
    onSurfaceVariant     = GhostText,
    outline              = CyanDim.copy(alpha = 0.4f),
    outlineVariant       = GridLine,
    surfaceContainerLow  = DeepConsole,
    surfaceContainer     = ConsolePanel,
    surfaceContainerHigh = Color(0xFF042233),
)

private val AmoledSciFiColorScheme = SciFiColorScheme.copy(
    background = Color(0xFF000000),
    surface    = Color(0xFF000000),
)

// ── Typography — monospace terminal feel ──────────────────────────────────────
// Using system monospace as fallback; project can add JetBrains Mono via assets
val SciFiTypography = Typography(
    displayLarge  = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Black,  fontSize = 57.sp, letterSpacing = (-0.5).sp),
    displayMedium = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.ExtraBold, fontSize = 45.sp),
    displaySmall  = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,  fontSize = 36.sp, letterSpacing = 1.sp),
    headlineLarge = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,  fontSize = 32.sp, letterSpacing = 2.sp),
    headlineMedium= TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 28.sp, letterSpacing = 1.5.sp),
    headlineSmall = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 24.sp, letterSpacing = 1.sp),
    titleLarge    = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,  fontSize = 22.sp, letterSpacing = 1.sp),
    titleMedium   = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, letterSpacing = 2.sp),
    titleSmall    = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium, fontSize = 14.sp, letterSpacing = 1.5.sp),
    bodyLarge     = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 16.sp, letterSpacing = 0.5.sp),
    bodyMedium    = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 14.sp, letterSpacing = 0.25.sp),
    bodySmall     = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp, letterSpacing = 0.4.sp),
    labelLarge    = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,  fontSize = 14.sp, letterSpacing = 2.sp),
    labelMedium   = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium, fontSize = 12.sp, letterSpacing = 1.5.sp),
    labelSmall    = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium, fontSize = 11.sp, letterSpacing = 2.sp),
)

@Composable
fun OxidOHTheme(
    darkTheme: Boolean = true,
    amoled: Boolean = false,
    dynamicColor: Boolean = false, // disabled — sci-fi theme overrides dynamic color
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        amoled -> AmoledSciFiColorScheme
        !darkTheme -> LightSciFiColorScheme
        else -> SciFiColorScheme
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            val insetsController = WindowCompat.getInsetsController(window, view)
            insetsController.isAppearanceLightStatusBars = !darkTheme
            insetsController.isAppearanceLightNavigationBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography  = SciFiTypography,
        content     = content
    )
}

