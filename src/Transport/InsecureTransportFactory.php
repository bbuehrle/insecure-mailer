<?php

namespace Symfony\Component\Mailer\Bridge\InsecureMailer\Transport;

use Symfony\Component\Mailer\Exception\IncompleteDsnException;
use Symfony\Component\Mailer\Exception\UnsupportedSchemeException;
use Symfony\Component\Mailer\Transport\Dsn;
use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Symfony\Component\Mailer\Transport\Smtp\Stream\SocketStream;
use Symfony\Component\Mailer\Transport\TransportInterface;

final class InsecureTransportFactory extends \Symfony\Component\Mailer\Transport\AbstractTransportFactory
{
    /**
     * @throws IncompleteDsnException
     * @throws UnsupportedSchemeException
     *
     * @return EsmtpTransport
     */
    public function create(Dsn $dsn): TransportInterface
    {
        if (!$this->supports($dsn)) {
            throw new UnsupportedSchemeException($dsn, 'smtp-insecure', $this->getSupportedSchemes());
        }

        $port = $dsn->getPort(0);
        $host = $dsn->getHost();

        $transport = new EsmtpTransport($host, $port, null, $this->dispatcher, $this->logger);

        /** @var SocketStream $stream */
        $stream = $transport->getStream();
        $streamOptions = $stream->getStreamOptions();

        if ('' !== $dsn->getOption('verify_peer') && !filter_var($dsn->getOption('verify_peer', true), \FILTER_VALIDATE_BOOLEAN)) {
            $streamOptions['ssl']['verify_peer'] = false;
            $streamOptions['ssl']['verify_peer_name'] = false;
        }

        $streamOptions['ssl']['security_level'] = 1;

        $stream->setStreamOptions($streamOptions);

        if ($user = $this->getUser($dsn)) {
            $transport->setUsername($user);
        }

        if ($password = $this->getPassword($dsn)) {
            $transport->setPassword($password);
        }

        if (null !== ($localDomain = $dsn->getOption('local_domain'))) {
            $transport->setLocalDomain($localDomain);
        }

        if (null !== ($restartThreshold = $dsn->getOption('restart_threshold'))) {
            $transport->setRestartThreshold((int) $restartThreshold, (int) $dsn->getOption('restart_threshold_sleep', 0));
        }

        if (null !== ($pingThreshold = $dsn->getOption('ping_threshold'))) {
            $transport->setPingThreshold((int) $pingThreshold);
        }

        return $transport;
    }

    protected function getSupportedSchemes(): array
    {
        return ['smtp+ds'];
    }

}
