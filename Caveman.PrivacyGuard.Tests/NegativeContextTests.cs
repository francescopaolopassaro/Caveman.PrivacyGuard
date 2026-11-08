using NUnit.Framework;
using Caveman.PrivacyGuard;
using System.Linq;

namespace Caveman.PrivacyGuard.Tests;

/// <summary>Anti-trigger (negative context) false-positive suppression for bare numeric candidates.</summary>
[TestFixture]
public class NegativeContextTests
{
    private PrivacyAnalyzer _a = null!;

    [SetUp]
    public void Setup() => _a = new PrivacyAnalyzer();

    [TestCase("Per qualsiasi problema puoi chiamarmi al cellulare 3389123456 domani.")]
    [TestCase("Il mio numero di telefono è 3389123456, anno 2024")]
    [TestCase("tel 3389123456")]
    [TestCase("Call me on the phone 5551234567 before the order ships")]
    [TestCase("Ruf mich an, Telefon 5551234567")]
    public void Analyze_RealPhoneWithContext_IsStillDetected(string text)
        => Assert.That(_a.Analyze(text).DetectedCategories, Does.Contain("Phone E.164"), text);

    [TestCase("Il codice articolo del prodotto è 3389123456, verificare magazzino.")]
    [TestCase("numero fattura 3389123456")]
    [TestCase("Ordine n. 3389123456 numero spedizione")]
    [TestCase("Invoice number 5551234567 for the order")]
    [TestCase("Rechnung Nummer 5551234567")]
    [TestCase("tracking 5551234567 tel")]
    public void Analyze_NumberLabelledAsCodeOrDocument_IsNotPhone(string text)
        => Assert.That(_a.Analyze(text).DetectedCategories, Does.Not.Contain("Phone E.164"), text);

    [Test]
    public void Analyze_PlusPrefixedPhone_IsNeverVetoed()
        => Assert.That(_a.Analyze("codice articolo +39 333 1234567").DetectedCategories, Does.Contain("Phone E.164"));

    [Test]
    public void UseNegativeContext_Disabled_RestoresOldBehaviour()
    {
        _a.UseNegativeContext = false;
        Assert.That(_a.Analyze("numero fattura 3389123456 tel").DetectedCategories, Does.Contain("Phone E.164"));
    }

    [Test]
    public void AddNegativeKeywords_CustomWord_VetoesNearbyCandidate()
    {
        var text = "telefono pratica interna 3389123456";
        _a.AddNegativeKeywords("pratica interna");
        Assert.That(_a.Analyze(text).DetectedCategories, Does.Not.Contain("Phone E.164"));
    }

    [Test]
    public void LoadCustomYaml_GlobalNegativeKeywords_AreApplied()
    {
        var a = new PrivacyAnalyzer();
        a.LoadCustomYamlFromString("version: \"2.1\"\nglobal_negative_keywords: [\"badge\"]\ncountries: []\n");
        Assert.That(a.Analyze("telefono badge 3389123456").DetectedCategories, Does.Not.Contain("Phone E.164"));
    }

    [Test]
    public void Analyze_FiscalCodeKeywordContainingCodice_IsNotVetoed()
    {
        // "codice fiscale" is a positive keyword: it must win the tie against the anti-trigger "codice".
        var r = _a.Analyze("codice fiscale RSSMRA80A01H501U");
        Assert.That(r.DetectedCategories, Does.Contain("Italian Tax Code (CF)"));
    }
}
