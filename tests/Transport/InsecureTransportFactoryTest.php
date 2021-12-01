<?php

namespace Symfony\Component\Mailer\Bridge\InsecureMailer\Tests\Transport;

use Symfony\Component\Mailer\Bridge\InsecureMailer\Transport\InsecureTransportFactory;
use Symfony\Component\Mailer\Test\TransportFactoryTestCase;
use Symfony\Component\Mailer\Transport\Dsn;
use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Symfony\Component\Mailer\Transport\TransportFactoryInterface;

class InsecureTransportFactoryTest extends TransportFactoryTestCase
{

    private const HOST = 'mail4.hostingplatform.com';
    private const SCHEME = 'smtp+ds';
    public function getFactory(): TransportFactoryInterface
    {
        return new InsecureTransportFactory($this->dispatcher, $this->client, $this->logger);
    }

    public function supportsProvider(): iterable
    {
        yield [new Dsn(self::SCHEME, self::HOST), true];
    }

    public function createProvider(): iterable
    {
        $dsn = new Dsn(self::SCHEME, self::HOST, self::USER, self::PASSWORD, 587);
        $port = $dsn->getPort(0);
        $host = $dsn->getHost();
        $transport = new EsmtpTransport($host, $port, null, $this->dispatcher, $this->logger);
        $stream = $transport->getStream();
        $streamOptions = $stream->getStreamOptions();
        $streamOptions['ssl']['security_level'] = 1;
        $stream->setStreamOptions($streamOptions);
        if ($user = $dsn->getUser()) {
            $transport->setUsername($user);
        }

        if ($password = $dsn->getPassword()) {
            $transport->setPassword($password);
        }
        yield [$dsn, $transport];

        $dsn = new Dsn(self::SCHEME, self::HOST, self::USER, self::PASSWORD, 587, ['verify_peer' => 0]);
        $transport = new EsmtpTransport($host, $port, null, $this->dispatcher, $this->logger);
        $stream = $transport->getStream();
        $streamOptions = $stream->getStreamOptions();
        $streamOptions['ssl']['verify_peer'] = false;
        $streamOptions['ssl']['verify_peer_name'] = false;
        $streamOptions['ssl']['security_level'] = 1;
        $stream->setStreamOptions($streamOptions);
        if ($user = $dsn->getUser()) {
            $transport->setUsername($user);
        }

        if ($password = $dsn->getPassword()) {
            $transport->setPassword($password);
        }
        yield [$dsn, $transport];
    }

    public function incompleteDsnProvider(): iterable
    {
        yield [new Dsn(self::SCHEME, self::HOST, self::USER)];
        yield [new Dsn(self::SCHEME, self::HOST, null, self::PASSWORD)];
    }

    public function unsupportedSchemeProvider(): iterable
    {
        yield [
            new Dsn('smtps+ds', self::HOST, self::USER, self::PASSWORD),
            'The "smtps+ds" scheme is not supported; supported schemes for mailer "smtp-insecure" are: "smtp+ds".',
        ];
        yield [
            new Dsn('smtps+foo', self::HOST, self::USER, self::PASSWORD),
            'The "smtps+foo" scheme is not supported; supported schemes for mailer "smtp-insecure" are: "smtp+ds".',
        ];
        yield [
            new Dsn('smtp', self::HOST, self::USER, self::PASSWORD),
            'The "smtp" scheme is not supported; supported schemes for mailer "smtp-insecure" are: "smtp+ds".',
        ];
    }
}
