using NUnit.Framework;
using Caveman.PrivacyGuard;
using System.Linq;

namespace Caveman.PrivacyGuard.Tests;

/// <summary>Evolutive: printed IBAN, dotted cards, landlines, IP, URL, amounts, birth dates, protocols, real VAT checksums.</summary>
[TestFixture]
public class EnhancedDetectionTests
{
    private PrivacyAnalyzer _a = null!;

    [SetUp]
    public void Setup() => _a = new PrivacyAnalyzer { EnableAutoMasking = true };

    private PrivacyAnalysisResult Run(string text) => _a.Analyze(text, "it", new PrivacySession());

    [TestCase("Bonifico su IBAN IT60 X054 2811 1010 0000 0123 456 intestato a Rossi", "intestato a Rossi")]
    [TestCase("IT60 X054 2811 1010 0000 0123 456 ROSSI MARIO", "ROSSI MARIO")]
    [TestCase("iban IT60-X054-2811-1010-0000-0123-456.", ".")]
    public void Iban_PrintedGrouped_IsMaskedWholeAndNeighbourWordsSurvive(string text, string mustSurvive)
    {
        var r = Run(text);
        Assert.That(r.DetectedCategories, Does.Contain("IBAN"));
        Assert.That(r.MaskedText, Does.Not.Contain("0123"));
        Assert.That(r.MaskedText, Does.Not.Contain("456"));
        Assert.That(r.MaskedText, Does.Contain(mustSurvive));
    }

    [Test]
    public void Iban_GroupedWithBadChecksum_IsNotMasked()
        => Assert.That(Run("IT60 X054 2811 1010 0000 0123 457").DetectedCategories, Does.Not.Contain("IBAN"));

    [TestCase("PAN 4111.1111.1111.1111.")]
    [TestCase("card 4111-1111-1111-1111")]
    [TestCase("Carta 4111 1111 1111 1111 12/26")]
    public void CreditCard_AnySeparator_IsDetected(string text)
        => Assert.That(Run(text).DetectedCategories, Does.Contain("Credit Card"));

    [Test]
    public void Phone_LandlineStartingWithZero_IsMaskedWholeNotJustTheTail()
    {
        var r = Run("Tel. fisso 010-2471234");
        Assert.That(r.MaskedText, Does.Not.Contain("010"));
        Assert.That(r.MaskedText, Does.Not.Contain("2471234"));
    }

    [TestCase("server 10.0.0.5 online")]
    [TestCase("rete 192.168.1.0/24 interna")]
    [TestCase("range 192.168.1.1-192.168.1.20")]
    public void IpAddress_WithNetworkContext_IsDetected(string text)
        => Assert.That(Run(text).DetectedCategories, Does.Contain("IP Address"));

    [TestCase("versione software 2.3.55.987 rilasciata")]
    [TestCase("changelog 1.2.3.4 build")]
    public void IpAddress_VersionNumbers_AreNotAddresses(string text)
        => Assert.That(Run(text).DetectedCategories, Does.Not.Contain("IP Address"));

    [Test]
    public void Url_SentencePunctuationIsNotPartOfIt()
    {
        var r = Run("Vedi https://example.it/pagina. Grazie");
        Assert.That(r.DetectedCategories, Does.Contain("URL"));
        Assert.That(r.MaskedText, Does.Contain(". Grazie"));
        Assert.That(r.MaskedText, Does.Not.Contain("example.it"));
    }

    [TestCase("sito www.esempio.it")]
    [TestCase("apri esempio.com ora")]
    public void Url_WwwAndBareKnownTld_AreDetected(string text)
        => Assert.That(Run(text).DetectedCategories, Does.Contain("URL"));

    [Test]
    public void Url_DomainOfAnEmailAddress_IsNotASecondUrl()
    {
        var r = Run("scrivi a mario.rossi@example.com");
        Assert.That(r.DetectedCategories, Does.Contain("Email"));
        Assert.That(r.DetectedCategories, Does.Not.Contain("URL"));
    }

    [TestCase("Totale € 1.234,56 da pagare")]
    [TestCase("Totale 1.234,56 euro da pagare")]
    [TestCase("pagati 50 € ieri")]
    public void Amount_IsDetectedAndEuroIsNotTruncated(string text)
    {
        var r = Run(text);
        Assert.That(r.DetectedCategories, Does.Contain("Monetary Amount"));
        Assert.That(r.MaskedText, Does.Not.Contain("euro"));
        Assert.That(r.MaskedText, Does.Not.Contain("€"));
    }

    [Test]
    public void BirthDate_OnlyNextToABirthKeyword()
    {
        Assert.That(Run("Nato il 06-11-2014 a Roma").DetectedCategories, Does.Contain("Date of Birth"));
        Assert.That(Run("Il file e stato salvato il 06-11-2014 alle 10").DetectedCategories, Does.Not.Contain("Date of Birth"));
    }

    [TestCase("Prot. n. 456/2024 del comune")]
    [TestCase("Rep. 12/2023")]
    [TestCase("protocollo 2024/55")]
    public void DocumentProtocol_WithOrWithoutNumberSign_IsDetected(string text)
        => Assert.That(Run(text).DetectedCategories, Does.Contain("Document Protocol Number"));

    [TestCase("P.IVA 00743110157 della societa")]
    [TestCase("partita iva IT00743110157")]
    public void ItalianVat_RealChecksum_IsDetected(string text)
        => Assert.That(Run(text).DetectedCategories, Does.Contain("Italian VAT Number"));

    [Test]
    public void ItalianVat_NumberLabelledAsArticleCode_IsNotDetected()
        => Assert.That(Run("Codice articolo 00743110157 a magazzino").DetectedCategories, Does.Not.Contain("Italian VAT Number"));

    [Test]
    public void AllEmbeddedRules_StillCompile()
        => Assert.That(_a.ValidateRules(), Is.True);
}
